---
summary: Thirteen capability layers, the v0 slice, the spine, the swap procedure, the reference environment, Ansible host trust, and what is built versus needs a server.
summary_of: outline:sha256:c158f9e6d12767fb
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Architecture: layers, seams and the spine

HomelabNext is **contracts, libraries and conformance tests**. It is not a platform, a framework
or a product. This page explains the shape that makes a product replaceable: thirteen capability
layers, a small "spine" of cross-cutting mechanisms, and one swap procedure. Decisions are
recorded in the [ADR log](adr/README.md); the Python interfaces are in
[interfaces.md](interfaces.md); the vocabulary is in [glossary.md](glossary.md).

## The principle

1. **The contract is the product; the implementation is a tenant.** For each layer, what you own
   and keep is the contract at its boundary: a schema, a protocol, an event type, a CLI shape.
   Products are current tenants of those contracts.
2. **Ports and adapters at seams, and only at seams.** Product-specific code lives in exactly one
   place per product: its provider module (ADR-0027), or, for a product with none yet, an adapter
   (a library module, a role, a generator) that the product-name lint counts in a baseline that
   only shrinks. Everything else talks to a logical name.
3. **Replaceability is measured, not asserted.** A capability counts as modular when a stranger
   can run its conformance test against the current implementation and it passes, the
   implementation is reachable only through a logical name, and its state has an exit in an open
   format.
4. **Names are the cheapest and highest-leverage indirection.** Most coupling is address
   coupling, so the first rule is: callers use a capability alias, never an address (ADR-0002).

### Where modularity is the wrong goal

- **The hypervisor is not a seam** (ADR-0012). Its exit is "restore from backup and rebuild from
  git", and the only test worth paying for is that rebuild.
- **No bus under the data plane** (ADR-0009). A bus carries reaction triggers, per-item records
  and decision events only (`docs/events.md`, "What goes on the bus"); telemetry stays a direct,
  buffered stream, and control stays typed request/response.
- **No internal framework.** The spine is libraries and generators. If a proposed abstraction
  needs its own service, database and on-call, it is a product and needs its own exit.
- **No lowest-common-denominator contracts.** Where an open standard is implemented well (S3,
  Iceberg REST, ANSI SQL, OCSF), the contract is that standard, not the intersection of every
  possible replacement.

## The thirteen layers

Each layer names the contract at its boundary and the test that proves a replacement compatible.
The "example tenants" are illustrations only: the reference environment in
`compose/lab-in-a-box/` uses the ones marked with an asterisk.

| # | Layer | Contract at the boundary | Example tenants | Conformance / swap test |
|---|---|---|---|---|
| 1 | Physical compute, storage, power | Restore and rebuild | any x86 host | rebuild from git, timed restore drill |
| 2 | Virtualisation and guest layout | Guest spec (name, id, network, cores, RAM, disks) | a hypervisor plus IaC | plan shows no diff; every guest has inventory, registry row, backup |
| 3 | Network segmentation and sensing | Zone reachability matrix (default deny) | a router or firewall | reachability probe run from inside each zone |
| 4 | Identity, secrets, access | OIDC (discovery, JWKS, token verify); one forward-auth identity-header set (`homelabnext.edge_identity`); one group-to-role table (registry `roles`); key issue/revoke API (ADR-0034) | an OIDC IdP (Keycloak by default), an auth proxy (oauth2-proxy by default) next to the edge, OpenBao* | `idp` suite; the generated realm grants each app exactly the table's roles; the edge lint (F-23) for the declared header set |
| 5 | Telemetry collection | Syslog/JSON over TLS, OpenMetrics, a source census | agents, shippers | census plus a canary event through the first hops |
| 6 | Data platform: storage, catalog, query | S3 API, Iceberg REST, ANSI SQL, pinned OCSF schemas | Garage*, Lakekeeper*, Trino* | `lake-query`, `lake-catalog`, `object-store` suites |
| 7 | Detection and correlation | Sigma rules with fixtures, cited by `det:<slug>` | a SIEM or rule engine | fixture runner with an engine adapter |
| 8 | Case management and DFIR | Case round trip (create, dedup, comment, close) | a case system (fake*) | `cases` suite |
| 9 | Threat intelligence | Typed indicators and reports in the lake | a TIP, feeds | schema validation plus replay |
| 10 | Internal assessment, detection and code security | Authorized internal assessment plans and findings as typed records (own environment only; [terms](terms.md)) | auditing tools | detection fixtures and coverage map |
| 11 | LLM serving, orchestration, agents | OpenAI-compatible chat; model-role aliases (ADR-0007); scoped context retrieval; Code Mode programs in a broker-only sandbox (ADR-0031) | an inference server (fake*), a context store, a sandbox host | `inference`, `context`, `codemode-executor` and `codemode-runner` suites, golden tasks |
| 12 | Observability, alerting, backup, power | OpenMetrics, state-diffed paging, export hooks (ADR-0008) | a metrics stack, ntfy* | `notify` suite; restore drill |
| 13 | Governance and control plane | Records lifecycle as an API (ADR-0010), approvals bound to a request digest; projects and work items linked to strategy records by uid (ADR-0020) | a broker, the records library, a project tool (OpenProject) | lifecycle and fixture runs, `projects` suite |

Eighteen core capabilities carry a conformance suite (fourteen at first drop, ADR-0005, then
`context`, `projects`, `codemode-executor` and `codemode-runner`); the list is authoritative in [interfaces.md](interfaces.md).
`make conform-check` and invariant X-10 count sixteen of them: `codemode-executor` and
`codemode-runner` belong to a frozen component ([tools/experimental.yml](../tools/experimental.yml)), so
their suites run in `make experimental` instead. Extended suites (`backup`, `dns`, `edge` and others,
[conformance.md](conformance.md)) ship beside them and run in CI too, outside that count. The platform names
more capabilities than either list (`hypervisor`, `metrics`, the module slots): every one is
classed in `homelabnext/agent/tool_classes.yml`, and a guest may declare any of them.

## The v0 slice

Not every layer is built at once. The first lab runs a small slice (operator decision,
2026-10-31; [build order](build-order.md), "The v0 slice"): the **registry and aliases**,
**OpenBao** (secrets), the **lake** (Garage, Lakekeeper, Trino), **Sigma detections**, the
**broker**, **notify**, the **status hub**, and **SSO** through Keycloak (ADR-0034, in flight).
The LLM gateway is LiteLLM alone (ADR-0022, amended). Projects and tasks live in OpenProject
only; the lessons, runbooks and invariants registers stay.

The rest keeps its contracts and code but not all of it blocks a merge: StackStorm is
*experimental*, and Code Mode (layer 11), the strategy stack and the home-built projects store
(layer 13) are *frozen*. `tools/experimental.yml` is the one list of them; their gates and tests
run in `make experimental` and CI's non-blocking `experimental` job instead of `make check`. The
playbook engine (StackStorm) and the orchestration controller (the operator's Go controller) are
not competing engines: the first decides when a workflow pack runs, the second schedules agent
sessions, and a pack reaches the controller only through the broker
([workflows](workflows.md)).

## The spine

The spine is the small set of mechanisms that make every swap cheap. All of it is libraries,
generators, DNS records and YAML.

| Mechanism | What it is | Where |
|---|---|---|
| **Schemas in git** | Contracts are JSON Schema files, additive evolution only, vendor schemas pinned, frozen baselines checked in CI | `schemas/`, `tools/schema_check.py` (ADR-0001) |
| **Registry and aliases** | One `services.yml`; every capability reachable as `<capability>.svc.<domain>`; an environment override for tests and staging; a CI gate against raw endpoints | `homelabnext/registry/`, `tools/no_raw_endpoints.py` (ADR-0002) |
| **Shared client libraries** | One library per data seam (lake, notify, state, records, events), each with an in-memory fake | `homelabnext/` (ADR-0003) |
| **Role interface** | Roles declare an argument spec and six hook task sets (health, readiness, backup, restore, upgrade, export); inventory groups are capabilities | `ansible/`, `tools/role_lint.py` (ADR-0004) |
| **Conformance harness** | One runnable swap test per capability, run against a fake in CI and against real containers nightly | `conformance/`, `compose/lab-in-a-box/` (ADR-0005) |
| **Detections as code** | Sigma rules plus fixtures, cited by logical id, never by an engine's rule number | `detections/` (ADR-0006) |
| **Model-role aliases** | Consumers name a role; only the gateway maps roles to backends | `homelabnext/registry/models.py` (ADR-0007) |
| **Export hooks** | Every stateful product has an export path exercised by a restore drill | role interface (ADR-0008) |
| **Records lifecycle** | Propose, approve, complete as an API; one validated write path for agents | `homelabnext/records/` (ADR-0010) |
| **Registers and invariants** | Generated registers (tasks, lessons, runbooks) and a runner for continuously-true properties | `homelabnext/registers/`, `homelabnext/invariants/` |

### How the pieces are meant to be adopted

Registry first (names, not addresses), then aliases (capability DNS names, ADR-0002, and model
roles, ADR-0007), then the shared libraries, then the conformance harness, then the role
interface. Each step is useful on its own and none requires the next.

## The swap procedure

Every product replacement follows one procedure (ADR-0005):

1. The swap test exists and the incumbent passes it.
2. The candidate is brought up on staging and passes the contract test.
3. Shadow or dual-run with idempotency keys.
4. Parity is held for a declared window.
5. Cutover by changing the registry `impl:` (or the DNS alias) and regenerating.
6. Verify: canaries and the affected invariants.
7. Rollback window with the old component stopped, not destroyed.
8. Decommission through the drift check (inventory, registry, monitoring, backup, DNS and docs
   must all forget the component in one change).
9. Record the swap, and update the ADR with a revisit trigger.

A swap that edits anything other than the registry row, the adapter and generated artefacts at
cutover is a defect to be recorded as a lesson.

## The reference environment

`compose/lab-in-a-box/` stands up a laptop- and CI-sized instance of the data, events, secrets,
notification and inference seams inside a 4 GB RAM budget, addressed through the
same `<capability>.svc.example.internal` aliases a real deployment uses. It is the place where
the conformance suites run against real containers rather than fakes (nightly, and on every pull
request that can affect the stack: CI's `lab-in-a-box` job, with the LLM gateway profile in `lab-gateway`, both summed up by `lab-ok`). It is a rehearsal environment, not a deployment: every credential is a throwaway and
every service is single node. See the README "Try it" section.

| Alias | Service | Capability |
|---|---|---|
| `object-store` | Garage (S3 API) | `object-store` |
| `lake-catalog` | Lakekeeper over Postgres (Iceberg REST) | `lake-catalog` |
| `lake-query` | Trino, single node, small heap | `lake-query` |
| `events` | NATS with JetStream | `events` |
| `secrets` | OpenBao in dev mode | `secrets` |
| `notify` | ntfy | `notify` |
| `inference` | the project's fake OpenAI-compatible server | `inference` |
| `cases` | the project's fake case system | `cases` |
| `metrics` | Prometheus, scraping itself, two always-firing rules | (status hub source) |
| `uptime` | Uptime Kuma, provisioned headlessly with a public status page | (status hub source) |
| `broker`, `status-hub`, `broker-edge` | `hnx broker serve` on a Unix socket, `hnx status serve` with the Approvals page, and the edge that drives them, each as its own uid (no alias for `broker`: it has no network) | `broker` (the end-to-end check below) |

The object store is Garage v2 (`dxflrs/garage:v2.5.0`). `lab_init.py` speaks Garage's admin API
v2 (`/v2/<Operation>`: `GetNodeInfo`, `UpdateClusterLayout`, `ApplyClusterLayout`, `ImportKey`,
`UpdateKey`, `CreateBucket`, `AllowBucketKey`, ...); the v1 admin API it used before is mostly gone
in v2, and `replication_mode` is no longer a configuration key (the lab's `garage.toml` uses
`replication_factor`). A fresh lab needs nothing. A site carrying a Garage v1 cluster's volumes
over follows the upstream
[migration to v2](https://garagehq.deuxfleurs.fr/documentation/working-documents/migration-2/):
`garage repair --all-nodes --yes tables`, a metadata snapshot (`garage meta snapshot --all`, or
a filesystem snapshot of `metadata_dir`), then stop every v1 node and start them all on v2 at
once; any of its own tooling that calls the admin API moves to the v2 endpoints too. `lab_init`
imports the lab's S3 key once and Garage v2 refuses to import a key id it has ever held (409
`KeyAlreadyExists`, even after the key is deleted), so a changed `LAB_S3_ACCESS_KEY` or
`LAB_S3_SECRET_KEY` on a kept volume needs `docker compose down -v` first.

The catalog database is PostgreSQL 18 (`postgres:18.6-alpine`). From 18 the official image keeps
its data at `/var/lib/postgresql/18/docker` (`PGDATA`) under a volume at `/var/lib/postgresql`,
so the lab mounts `postgres-data` there, not at the old `/var/lib/postgresql/data`; a later major
gets its own `<major>/docker` beside it, which is what lets `pg_upgrade --link` work inside one
mount. A major upgrade never converts data: the entrypoint refuses a volume an older server
initialised (after creating an empty `18/docker` in it), so a lab recreates it
(`docker compose down -v`) and a site with data to keep dumps and restores, or runs `pg_upgrade`,
first. For `pg_upgrade` the clusters must agree on data checksums: one the 16 image made has them
off and 18's `initdb` turns them on, so initialise the 18 cluster with
`POSTGRES_INITDB_ARGS=--no-data-checksums` (or `pg_checksums --enable` the stopped 16 cluster
first); a dump and restore is unaffected. The healthcheck probes over TCP because the entrypoint's
init server listens on the socket only, so postgres is not reported healthy mid-initialisation.

The lake catalog is Lakekeeper 0.14 (`quay.io/lakekeeper/catalog:v0.14.1`; `catalog-migrate`
runs its `migrate` before `serve`, so a kept Postgres volume from 0.9 is migrated forward on the
first start, one way). Three upstream changes since 0.9 matter here:

- **How clients reach the table files (0.11).** A client that sends no
  `X-Iceberg-Access-Delegation` header now gets vended credentials (always a temporary STS, R2
  or OSS credential, never the stored key) whenever the warehouse can issue them (STS on, or a
  Cloudflare R2 or Alibaba OSS credential), else remote signing. The lab's warehouse states both
  modes rather than relying on that default: `lab_init.py` creates it with `sts-enabled: false`
  and `remote-signing-enabled: true` and an access-key credential, so no credential is vended
  and clients get remote signing (already the 0.9 behaviour) or nothing, and Trino keeps
  `iceberg.rest-catalog.vended-credentials-enabled=false` and reads the object store with its
  own keys. A production warehouse that wants vended credentials enables STS against an object
  store that offers it, with a role scoped to the warehouse's prefix.
- **Storage layout (0.13).** A namespace created from 0.13 on keeps its tables at
  `<warehouse base>/<table uuid>` (it was `<base>/<namespace uuid>/<table uuid>`); namespaces
  created earlier keep the old layout, and a warehouse can set `storage-layout` explicitly.
  Nothing here derives a path from the layout: table locations are read from the catalog.
- **Authentication (0.14), for the production row below.** `LAKEKEEPER__OPENID_SCOPE` is a single
  word and needs `LAKEKEEPER__OPENID_PROVIDER_URI` (an empty value no longer means "no scope");
  an unknown key under `LAKEKEEPER__OPENID_PROVIDERS__<IDP_ID>__` aborts startup; such a provider
  that enforces a scope or required claims must keep `__REQUIRE_CONNECTED_ON_STARTUP` at its
  default, `true`; Kubernetes authentication beside a provider that enforces either needs
  `LAKEKEEPER__KUBERNETES_AUTHENTICATION_AUDIENCE`. The scope is read from the token's `scp`
  claim only when `scope` carries none, and an array-shaped scope claim is accepted. Token roles and admission gates now hold in every project, and the
  permissions-check API no longer accepts the `update_storage_credential` action (use
  `update_storage`).

The metrics service is Prometheus 3 (`prom/prometheus:v3.15.1`, the busybox image, so its
`wget` healthcheck stands). Its 2-hour retention is `storage.tsdb.retention.time` in
`config/prometheus/prometheus.yml`, since the `--storage.tsdb.retention.time` flag is deprecated.
The status hub's `poll-prometheus` collector reads 3.x's `/api/v1/query` and `/api/v1/alerts`
unchanged. For a production Prometheus, 3.0 broke several things
([migration guide](https://prometheus.io/docs/prometheus/latest/migration/)):

- A scrape whose `Content-Type` is missing or unknown fails, where 2.x read it as the text
  format. The lab scrapes only itself, which is verified. The example registry's endpoints are
  expected to be fine, because each is served by a Prometheus client library that sets a
  supported type (Lakekeeper's `metrics-exporter-prometheus` sends `text/plain`, read in its
  source); the others are inferred from the library each product uses, not tested against a
  live endpoint. So the generated `scrape_configs` set no `fallback_scrape_protocol`.
  A generated job is "do not edit", so a site cannot add a fallback to it by hand. When a
  target does need one, the plan is an optional, pattern-validated registry field
  `metrics.fallback_protocol` that the generator copies into that job. The protocol name then
  lives in site data, not core code. Until that field exists, a site keeps such a target out of
  the generated file and writes the job in its own scrape config.
- UTF-8 metric and label names are valid by default (`metric_name_validation_scheme: legacy`
  restores the old check).
- Classic-histogram `le` and summary `quantile` values are normalised to floats on ingestion, so
  a rule or dashboard matching `le="1"` must match `le="1.0"`.
- Range selectors and lookback are left-open.
- `holt_winters` is `double_exponential_smoothing`, behind
  `--enable-feature=promql-experimental-functions`.
- `scrape_classic_histograms` is `always_scrape_classic_histograms`.
- Alertmanager's v1 API is gone (`api_version: v2`, Alertmanager 0.16 or later).
- The `--storage.tsdb.retention` and `--alertmanager.timeout` flags are removed.

Nothing in this repository's rules or generated config used any of these.
`tests/compose/test_lab_in_a_box.py` fails if the lab's config brings one back. A kept 2.x data
directory opens in 3.x, but after that it can be downgraded only to 2.55.

The query engine is Trino 484 (`trinodb/trino:484`, on JDK 25). Since 484 its image is built on
Red Hat's hardened core runtime, which has no `grep`, so the healthcheck runs the image's own
`/usr/lib/trino/bin/health-check` (curl and bash builtins), and the image no longer has the
`run-trino` wrapper that set the node id, so the lab's `node.properties` sets
`node.id=${ENV:HOSTNAME}` itself (a node id must match `[A-Za-z0-9][_A-Za-z0-9-]*`, so an
overlay that gives the service a dotted `hostname:` fails at start). Trino's launcher (airlift
launcher 321) appends a set of options per JDK major (21 to 28) after `jvm.config`; for JDK 25
they are `-XX:+EnableDynamicAgentLoading`, `--add-modules=jdk.incubator.vector`,
`--sun-misc-unsafe-memory-access=allow`, `--enable-native-access=ALL-UNNAMED` and
`-XX:+UseCompactObjectHeaders` (plus `-XX:-RewriteBytecodes` on arm64). The lab's `jvm.config`
therefore sets none of them: only heap, GC and diagnostics options (with the image default
`-XX:-OmitStackTraceInFastThrow`). The mounted `config/trino/` replaces the whole `/etc/trino`, so it holds exactly
`config.properties`, `jvm.config`, `node.properties` and `catalog/*.properties` (a
`secrets.toml` there would replace the environment-variable resolver behind `${ENV:...}`). The Iceberg catalog turns on the native S3 file system by its
current name, `fs.s3.enabled` (the legacy S3 file system is gone since 481, and
`fs.native-s3.enabled` is only a deprecated alias). Releases 471 to 484 also changed SQL
semantics the repository's adapters do not rely on: decimal arithmetic precision (477), `char` to
`varchar` coercion (482), typed `lower_bounds`/`upper_bounds` in the Iceberg `$files` table (482),
and in 484 JSON values that keep numeric types and member order, UTC timestamps in the Iceberg
`$snapshots` and `$history` tables, case-preserved user names in `GRANT`, and interval
arithmetic. A site's own queries over the lake are worth re-reading against the
[release notes](https://trino.io/docs/current/release.html). The redesigned Web UI is now at
`/ui` (the previous one at `/ui/legacy`, off by default).

**The broker end to end.** The smoke's `broker` check runs `broker_e2e.py run` inside
`broker-edge` against the real broker and hub containers: the broker serves
`examples/broker/manifest.production.yml` (callers and the relay by system user) on a socket in a
shared volume and has no network at all; the hub (user `hnx-hub`, the manifest's relay) serves
`/approvals` behind a front door whose one trusted proxy is the edge's fixed address
(`LAB_BROKER_EDGE_ADDRESS`); the edge, root with only `SETUID`/`SETGID`, starts the agent's
`hnx broker mcp` as `hnx-agent-triage` under a real MCP stdio client, an unmapped uid, and the
relay's audit read, and plays the edge for the approver. What it asserts, step by step:
[broker testing](broker.md#testing). `make lab-broker` runs only these three containers.

### It is not a deployment: what replaces each service in production

The lab trades every protection for a small footprint, so it binds published ports to loopback
only. `smoke.sh` and `make lab-up` refuse any other `LAB_BIND` unless
`LAB_I_UNDERSTAND_UNAUTHENTICATED=1` is set **and** every credential differs from its
`.env.example` placeholder (`compose/lab-in-a-box/bind_guard.sh`, which judges the configuration
`docker compose config` resolves, refuses a `.env` line it cannot read, and refuses when it
cannot resolve the configuration at all); docker publishes ports through
its own firewall rules, ahead of ufw or firewalld, so a host firewall is no substitute. Containers
run with `no-new-privileges` and `cap_drop: [ALL]` (postgres adds back what its entrypoint needs;
Uptime Kuma runs its rootless image, as the image's `node` user). A real deployment changes each
service as follows:

| Lab service | Lab shortcut | Production replacement |
|---|---|---|
| `secrets` (OpenBao) | dev mode: in memory, no TLS, a known root token, starts unsealed | server mode with integrated (raft) storage, TLS, real unseal keys or auto-unseal, root token revoked after initialisation, short-lived per-client tokens |
| `object-store` (Garage) | known RPC secret and admin token, single node, plain HTTP | generated secrets from the secrets capability, replicated layout, TLS at the edge, admin API on the management zone only |
| `postgres` | known password, `fsync=off` | generated password, `fsync` on, TLS, backups in the restore drill |
| `lake-catalog` (Lakekeeper) | no authentication, known encryption key | OIDC through the IdP, encryption key from the secrets capability |
| `lake-query` (Trino) | no authentication, plain HTTP | TLS plus OIDC or password authentication and access control (S-02) |
| `events` (NATS) | accounts with per-user passwords and subject permissions (`config/nats/nats.conf`), plain TCP | per-client credentials (NKeys or JWT) and TLS |
| `notify` (ntfy) | open publish and subscribe | `auth-default-access: deny-all` with per-topic users or tokens, behind the forward-auth proxy |
| `inference`, `cases` | the project's fakes | the real inference server and case system behind the same aliases |
| `metrics` (Prometheus) | no authentication, 2-hour retention, rules that always fire | the real metrics service with its own rules, behind the forward-auth proxy |
| `uptime` (Uptime Kuma) | a known admin password, a public status page | a generated admin password, 2FA, behind the forward-auth proxy; only the monitors the hub should see on the public page |
| `broker`, `status-hub`, `broker-edge` | a known front-door secret, an edge that asserts the approver's identity without a login, the example handlers | the systemd unit in [broker](broker.md#a-systemd-unit) with the operator's manifest and handlers, the hub behind Caddy, the auth proxy and the IdP (ADR-0034) with the front-door secret from the secrets capability |

## Ansible host trust

`ansible/ansible.cfg` keeps host key checking on. Ansible pushes configuration and secrets to
hosts that grant it sudo, so an unverified host key would hand them to whoever answers on the
address. Trust is bootstrapped once, out of band: record each guest's key in `known_hosts` after
comparing its fingerprint with the one shown on the hypervisor console or in the cloud-init log
(`ssh-keyscan` collects it, `ssh-keygen -lf` prints the fingerprint), or sign host keys with an
SSH host CA and trust the CA once with an `@cert-authority` line. A guest cloned from a template
must regenerate its host keys on first boot (cloud-init does by default; a template never ships
`/etc/ssh/ssh_host_*`), otherwise every clone shares one key and a mismatch can no longer reveal an
impostor.

## What is built and what needs a real server

Phases are tagged **PUBLIC-NOW** (provable on a laptop or CI runner with fakes, fixtures and
containers) or **SERVER** (needs a real deployment; documented, with an interface and a fake
where one is useful, never pretended). The phase list is in [build-order.md](build-order.md) and
the per-property list in [checklist.md](checklist.md).
