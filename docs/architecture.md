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
   place per product: an adapter (a library module, a role, a generator). Everything else talks
   to a logical name.
3. **Replaceability is measured, not asserted.** A capability counts as modular when a stranger
   can run its conformance test against the current implementation and it passes, the
   implementation is reachable only through a logical name, and its state has an exit in an open
   format.
4. **Names are the cheapest and highest-leverage indirection.** Most coupling is address
   coupling, so the first rule is: callers use a capability alias, never an address (ADR-0002).

### Where modularity is the wrong goal

- **The hypervisor is not a seam** (ADR-0012). Its exit is "restore from backup and rebuild from
  git", and the only test worth paying for is that rebuild.
- **No bus under the data plane** (ADR-0009). A bus belongs at the reaction seam only; telemetry
  stays a direct, buffered stream, and control stays typed request/response.
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
| 4 | Identity, secrets, access | OIDC; a forward-auth header set; key issue/revoke API | an IdP, a proxy, OpenBao* | each app accepts the same claim-to-role mapping |
| 5 | Telemetry collection | Syslog/JSON over TLS, OpenMetrics, a source census | agents, shippers | census plus a canary event through the first hops |
| 6 | Data platform: storage, catalog, query | S3 API, Iceberg REST, ANSI SQL, pinned OCSF schemas | Garage*, Lakekeeper*, Trino* | `lake-query`, `lake-catalog`, `object-store` suites |
| 7 | Detection and correlation | Sigma rules with fixtures, cited by `det:<slug>` | a SIEM or rule engine | fixture runner with an engine adapter |
| 8 | Case management and DFIR | Case round trip (create, dedup, comment, close) | a case system (fake*) | `cases` suite |
| 9 | Threat intelligence | Typed indicators and reports in the lake | a TIP, feeds | schema validation plus replay |
| 10 | Red, blue, purple, code security | Emulation plans and findings as typed records | emulation tooling | detection fixtures and coverage map |
| 11 | LLM serving, orchestration, agents | OpenAI-compatible chat; model-role aliases (ADR-0007) | an inference server (fake*) | `inference` suite, golden tasks |
| 12 | Observability, alerting, backup, power | OpenMetrics, state-diffed paging, export hooks (ADR-0008) | a metrics stack, ntfy* | `notify` suite; restore drill |
| 13 | Governance and control plane | Records lifecycle as an API (ADR-0010), approvals bound to a request digest | a broker, the records library | lifecycle and fixture runs |

Fourteen capabilities carry a conformance directory at first drop (ADR-0005); the list is
authoritative in [interfaces.md](interfaces.md).

## The spine

The spine is the small set of mechanisms that make every swap cheap. All of it is libraries,
generators, DNS records and YAML.

| Mechanism | What it is | Where |
|---|---|---|
| **Schemas in git** | Contracts are JSON Schema files, additive evolution only, vendor schemas pinned, frozen baselines checked in CI | `schemas/`, `tools/schema_check.py` (ADR-0001) |
| **Registry and aliases** | One `services.yml`; every capability reachable as `<capability>.svc.<domain>`; an environment override for tests and staging; a CI gate against raw endpoints | `homelabnext/registry/`, `tools/no_raw_endpoints.py` (ADR-0002) |
| **Shared client libraries** | One library per data seam (lake, notify, state, records, events), each with an in-memory fake | `homelabnext/` (ADR-0003) |
| **Role interface** | Roles declare an argument spec and five hook task sets (health, readiness, backup, upgrade, export); inventory groups are capabilities | `ansible/`, `tools/role_lint.py` (ADR-0004) |
| **Conformance harness** | One runnable swap test per capability, run against a fake in CI and against real containers nightly | `conformance/`, `compose/lab-in-a-box/` (ADR-0005) |
| **Detections as code** | Sigma rules plus fixtures, cited by logical id, never by an engine's rule number | `detections/` (ADR-0006) |
| **Model-role aliases** | Consumers name a role; only the gateway maps roles to backends | `homelabnext/registry/models.py` (ADR-0007) |
| **Export hooks** | Every stateful product has an export path exercised by a restore drill | role interface (ADR-0008) |
| **Records lifecycle** | Propose, approve, complete as an API; one validated write path for agents | `homelabnext/records/` (ADR-0010) |
| **Registers and invariants** | Generated registers (tasks, lessons, runbooks) and a runner for continuously-true properties | `homelabnext/registers/`, `homelabnext/invariants/` |

### How the pieces are meant to be adopted

Registry first (names), then aliases (DNS), then the shared libraries, then the conformance
harness, then roles. Each step is useful on its own and none requires the next.

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
the conformance suites run against real containers rather than fakes (nightly, never on a pull
request). It is a rehearsal environment, not a deployment: every credential is a throwaway and
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

### It is not a deployment: what replaces each service in production

The lab trades every protection for a small footprint, so it binds published ports to loopback
only. `smoke.sh` and `make lab-up` refuse any other `LAB_BIND` unless
`LAB_I_UNDERSTAND_UNAUTHENTICATED=1` is set **and** every credential differs from its
`.env.example` placeholder (`compose/lab-in-a-box/bind_guard.sh`); docker publishes ports through
its own firewall rules, ahead of ufw or firewalld, so a host firewall is no substitute. Containers
run with `no-new-privileges` and `cap_drop: [ALL]` (postgres adds back what its entrypoint needs;
OpenBao keeps docker's defaults). A real deployment changes each service as follows:

| Lab service | Lab shortcut | Production replacement |
|---|---|---|
| `secrets` (OpenBao) | dev mode: in memory, no TLS, a known root token, starts unsealed | server mode with integrated (raft) storage, TLS, real unseal keys or auto-unseal, root token revoked after initialisation, short-lived per-client tokens |
| `object-store` (Garage) | known RPC secret and admin token, single node, plain HTTP | generated secrets from the secrets capability, replicated layout, TLS at the edge, admin API on the management zone only |
| `postgres` | known password, `fsync=off` | generated password, `fsync` on, TLS, backups in the restore drill |
| `lake-catalog` (Lakekeeper) | no authentication, known encryption key | OIDC through the IdP, encryption key from the secrets capability |
| `lake-query` (Trino) | no authentication, plain HTTP | TLS plus OIDC or password authentication and access control (S-02) |
| `events` (NATS) | no authentication, plain TCP | accounts with per-client credentials (NKeys or JWT) and TLS |
| `notify` (ntfy) | open publish and subscribe | `auth-default-access: deny-all` with per-topic users or tokens, behind the forward-auth proxy |
| `inference`, `cases` | the project's fakes | the real inference server and case system behind the same aliases |

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
