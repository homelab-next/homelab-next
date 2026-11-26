<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `gateway`: the LLM gateway provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `inference` slot with **the lab's own LLM gateway** (`orchestrator/cmd/gateway`,
[docs/gateway.md](../../docs/gateway.md), ADR-0038): the one place where a model role becomes a
backend and a model id. It is a **service, not a machine**: the guest it runs on is the site's guest
file, and the site's selection places the module's one host role (`server`) on it. Nothing in this
directory names a real host, address, VM id, model or secret value; those live only in the private
overlay.

| | |
|---|---|
| Slot | `inference` (contract `conformance/protocols/inference.py`), stateless |
| Adapter | the shared `homelabnext.conform.adapters.llm_gateway:make`, features `streaming`, `gateway`, `turn-records` |
| Product | the lab's own gateway, `orchestrator/cmd/gateway`, as the image `image/Dockerfile` builds |
| Host role | `server`: kind `vm`, baseline `base`, footprint 1 vCPU, 512 MB, 10 GB |
| Role | `gateway` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the keys, read by name at deploy time) |
| Egress | `internet`, for the one cloud provider host the site allows |
| Public route | none: internal, every caller has its own key |

## Why the lab's own gateway, not LiteLLM

[ADR-0022](../../docs/adr/0022-llm-gateway-litellm.md) made LiteLLM the deployed gateway and
[ADR-0038](../../docs/adr/0038-the-llm-gateway-is-our-own-behind-the-same-contract.md) names this
one as its replacement behind the same contract. For the **new** lab there is nothing to run
beside it, and the choice is made on these facts:

- **LiteLLM needs a Postgres, a salt key and a key-provisioning step at every deploy** to serve
  what the lab uses (role aliases, ordered backends, fallbacks, per-key limits). This gateway reads
  one rendered file, holds no database, and a key is a line of the spec: adding or revoking one is
  a spec change and a restart, never an admin-API call that can be forgotten.
- **Supply chain.** LiteLLM is the fastest-moving pin in the lab (fourteen stable releases in
  fourteen days at the ADR-0022 evidence run) and had two compromises in 2026: a PyPI release in
  March and **1.107.0 in October, a credential stealer on PyPI and Docker Hub** (the old lab's
  incident of 2026-10-21, C2 `litellm.dev`). This gateway is Go, standard library only, built from
  this repository's own commit with no module download (`go.sum` is not even consulted for a
  dependency), and the image is **empty but for one static binary**. The role accepts an image only
  from the repositories the site lists (`gateway_build_repositories`, default the build's own
  `localhost/hnx-llm-gateway`); an image of any other repository is refused, whatever its tag or
  digest, and a test holds that.
- **It reads the request's TLP label** (`X-HNX-TLP`, ADR-0038 decision 5): a request above a
  role's ceiling is refused before any backend is called, and an unlabelled request to a role that
  leaves the lab is refused (`unlabelled`). LiteLLM can enforce key scope only.
- **The conformance suite already exists and passes.** CI's `gateway-conformance` job runs the
  `inference` suite (`streaming`, `embeddings`, `gateway`, `tlp-ceiling`, `tlp-admit`,
  `turn-records`) against this binary on every change. The image this module builds was also run
  through that suite as the module was written (24 checks, `--strict`, the binary extracted from the
  image, in a loopback-only network namespace).
- **Per-call usage records per caller** (`usage.jsonl`, read over `GET /v1/usage`) are what
  orchestration telemetry and the status hub read; it is the `turn-records` feature.

What it does not do, and the cost of choosing it: ADR-0038 decision 7 asks that the binary "has
served the lab beside LiteLLM" before cutover, and a **new lab has no LiteLLM beside it**, so that
clause is met by the CI job and by the gateway being new, not by a side-by-side run; the operator
may want to record that. Its limits are in memory (a restart clears the windows; one gateway, not
two), it speaks the OpenAI protocol and Anthropic's only, and the callers must send `X-HNX-TLP`
(and `X-HNX-Tag` for usage tagging) or a role that leaves the lab refuses them (docs/gateway.md,
"Cutover note: the callers' headers").

## What the role does

`roles/gateway`:

- **The configuration is data and is rendered on the controller** by the generator from the
  site's gateway spec: `hnx gen gateway render SPEC OUT`, then the same command with `--check` (the
  render audited against the spec and the locality rule), exactly as the metrics module renders its
  scrape targets. The spec names the role table (`model_roles.json`), the backends (by registry
  row, `svc:<row>`), the caller keys by `secret:` reference and their limits. **Nothing about a
  model, a backend or a caller is in the role.** The role then holds the rendered file to what it
  promises beside the generator's own audit: it is not a test-only rendering; its admin key is
  `gateway_admin_key_ref`; **every cloud deployment is `https` on a host in
  `gateway_cloud_hosts_allowed`** (default empty: no cloud binding is accepted); and no deployment
  names a host in `gateway_refused_hosts` (a site lists a host a model backend of the new lab must
  never be). The generator already refuses a "local" backend that is not a registry service in a
  lab zone, a local-only role with a cloud fallback, and an agent role that crosses providers.
- **The keys** come from the secret store by name and reach the container only through the
  compose `env_file` (`secrets/gateway.env`, 0600): never the compose file, the argv, the rendered
  config or a log. The config names environment variables; the role maps each to the one
  `secret:` reference it finds in the spec's text (or in `gateway_key_refs_extra`, for a key the
  generator names itself, such as one per agent profile) and refuses one it cannot place. Before
  anything is written it checks every key has the form the gateway demands at start (a caller's,
  the admin's and the telemetry reader's: 32 to 512 characters of `[A-Za-z0-9._~+/=-]`, all
  distinct and none a provider's), so a bad key is a named refusal at deploy, not a crash loop.
- **The container** is the image built by `image/Dockerfile` (below), run as `gateway_uid:gateway_gid`
  (61004, an id no account on the host has), every capability dropped, `no-new-privileges`, a **read-only
  root filesystem**, a memory limit, bounded logs and a healthcheck (a six-line Go probe in the image:
  `GET /healthz`). Its config is a read-only bind mount; its one writable path is `state/` (the usage
  file). It listens on 4100 inside; the host publishes it on the guest's own address only
  (`gateway_bind`; all interfaces is refused). The listen is plain http with `-allow-plaintext`: the
  callers reach it on a trusted segment behind the guest's firewall, as every internal service of
  the lab (registry `tls: none`); keys cross that segment in clear.
- **A changed config or key restarts it** (`docker compose restart -t 135`: SIGTERM drains calls in
  flight for the upstream timeout plus 5 s). The gateway reads both once, at start. A restart clears
  the rate-limit windows.
- **The image is the lab's own gateway**: an image from a repository not in `gateway_build_repositories` is refused, whatever its tag or digest.

Data lives under the module's data root `gateway_data_root` (`/var/lib/hnx-modules/gateway`):
`config/` (root's, readable by the container's group, mounted read-only), `state/` (the container's,
0700: `usage.jsonl`) and `export/` (the exit copy). The compose project is `gateway_dir`
(`/opt/compose/gateway`); its `secrets/gateway.env` (0600) holds every key.

## The image

There is **no published image to pin**: the gateway is code in this repository, and the image is
built from it. `image/Dockerfile` builds `orchestrator/cmd/gateway` with the Go the module pins
(`GOTOOLCHAIN=local`, `-mod=readonly`, `-trimpath`) from the repository root as the build context, and
copies the binary, a health probe and the certificate bundle the build image carries (the cloud
provider's API is verified against it) into `FROM scratch`: no shell, no package manager, a numeric
unprivileged user. The build image is pinned by digest (it is the one `compose/lab-in-a-box/orchestrator`
builds the controller with).

```bash
cd <a checkout of this repository at the commit the overlay pins>
docker build -f modules/gateway/image/Dockerfile -t hnx-llm-gateway:<version>-<commit12> .
docker image inspect --format '{{.Id}}' hnx-llm-gateway:<version>-<commit12>   # sha256:<digest>
docker save hnx-llm-gateway:<version>-<commit12> | zstd -o hnx-llm-gateway-<version>-<commit12>.tar.zst
sha256sum hnx-llm-gateway-<version>-<commit12>.tar.zst > hnx-llm-gateway-<version>-<commit12>.tar.zst.sha256
```

The reference the role takes is `gateway_image: localhost/hnx-llm-gateway:<version>-<commit12>@sha256:<digest>`
(a tag of this repository's own, which `compose_app` requires, and the digest, which Docker resolves). With
the containerd image store (the default of current Docker) the digest survives `docker save` and
`docker load`; the role loads `gateway_image_archive` (a path on the guest) when the daemon lacks the
digest and refuses to go on if it is still missing. **Verify the archive (`sha256sum -c`) before the
deploy**: the role checks the digest after the load, not the archive's hash. A rebuild from the same commit
is not guaranteed to give the same digest; the pin is the digest the operator built and recorded. The tag's
`<version>` is the module's `product.version`.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness; the spec renders and passes the generator's audit and this role's checks (above); every key the config names resolves and has its form |
| `health` | every container of the spec running and healthy; `GET /healthz` is 200, `status: ok` and **no usage record dropped**; a call **without a key and a call with a wrong key are each refused** (401 or 403); the admin key lists **exactly the role aliases of the installed config** (so the running process serves the file on disk); and `usage.jsonl` is within `gateway_usage_max_mb` (2 GiB; the gateway does not rotate it). It calls no model |
| `export` | `export/usage.jsonl` (the records up to the last complete line, each a JSON object) and `export/listing.jsonl` (key, lines, size, sha256), as the container's user (`setpriv` when the play runs as root) |
| `backup` | the export, then `compose_app`'s backup manifest (the data root, export included) |
| `restore` | one script, two passes, run as root. **Check** (nothing written): the source and each file opened without following a link, owned by root or the container's user and writable by no one else; a listing naming exactly `usage.jsonl`; a single-link regular file of the listed size, sha256 and line count whose every line is a record. **Apply** (gateway stopped): staged beside the live file, hashed again, renamed into place as the container's user (0600); the gateway is started again whatever happened |
| `upgrade` | refuses a target not pinned by tag and digest, with the tag `latest`, or from another repository, then records the bump (`compose_app` upgrade) |

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file** (`lab/guests/<name>.yml`): the module's `server` role goes on a guest that has
   `docker_engine`. Its `firewall_rules` (rendered to the hypervisor's per-VM firewall, the control for
   the published port; a host-firewall rule *inside* the guest does not see Docker's published ports)
   admit **inbound** the callers on 4100 and **outbound** only the backends and the cloud provider's
   address range on 443. The role cannot enforce the egress itself: the container has its own network
   namespace, so the generated cgroup policy of `egress:` does not cover it (`hnx modules check` warns).
2. **The selection** (`lab/modules.yml`): `hosts.<name>: {guest: guest:<name>}`, and
   `slots.inference: [{provider: gateway, instance: <instance>, placement: {server: <name>}}]`; remove the
   slot from `planned`. **The grant**, in the same change: `grants.egress.gateway.server: [internet]`.
   An instance named like a core registry row needs that row's capability to be `inference`.
3. **The registry row**: `registry/services.yml`'s `inference` row renamed to the instance, `host` the
   guest's name, `version: "0.1.0"`, plus at most `standing`, `backup_job` and `scope`. The backends it
   calls are **their own rows** (`svc:<row>` in the spec) in the lab registry, in a lab zone.
4. **The gateway spec** (the file `gateway_spec` names; the generator's format, `docs/llm-gateway.md`) and
   the role table `model_roles.json` it names: roles with ordered bindings (local first, the cloud binding
   last with `leaves_lab: true`; an optional `priority >= 1` on every binding of a role ranks them,
   and with LiteLLM equal priorities are load-balanced, while this own gateway still fails over in
   order and does not balance them), the backends (`svc:<registry row>: {locality: local}`; a cloud one
   `{locality: cloud, provider: anthropic, api_key: secret:gateway/upstream-cloud}`), `master_key`,
   `telemetry_reader`, and **one `keys:` entry per caller** with its roles, `data_tier`, `tlp_ceiling` and
   limits. The spec requires a `database_url:` reference the own gateway never reads (a LiteLLM leftover of
   the spec format): name any `secret:` reference, it is not resolved.
5. **The secrets**, by name, in the secret store: `gateway/master-key` and one `gateway/key-<caller>` per
   caller (each a random token of 32 bytes or more, e.g. `sk-` and 64 hex), `gateway/key-telemetry-reader`
   (read-only), and `gateway/upstream-cloud` (the provider's console: an API key with a spend limit).
   The names are the spec's; the role places each environment variable the config names on the reference
   it finds in the spec's text.
6. **The role's variables** (the overlay's `group_vars/mod_gateway_server.yml`): `gateway_logical_id`,
   `gateway_spec` (an absolute path on the controller), `gateway_spec_root` (the checkout the spec and its
   role table live in, an absolute path: the render runs from the deploy directory, outside it, and refuses a
   role table it cannot place inside a root), `gateway_image` (above), `gateway_cloud_hosts_allowed:
   [<the provider's API host>]`, and the lab's `gateway_refused_hosts`.
7. **Apply**: `docker_engine` on `mod_gateway_server`, then the rendered `modules.yml` twice (the second
   `changed=0`), then `checks/gateway.yml`.
8. **Prove it against the real server**: the conformance run below.

## Conformance

`conformance/target.yml` is the `inference` suite through the shared gateway adapter, with the features
that call only **local** roles (`streaming`, `gateway`, `turn-records`): a run against the
lab's instance spends nothing at the cloud provider. It needs, in a copy of the file, `allow_plaintext:
true` (the lab's http), the lab's role table path, a chat role, and in the spec a
`conformance-throttle` key (local-only, `window_s: 60`, `max_requests: 3`) and the telemetry reader. The
cloud-facing checks (`tlp-ceiling`, `tlp-admit`, the refused-fallback check) run in this repository's CI
against the fake inference server, on the same source.

```bash
HNX_ENDPOINT_INFERENCE=http://<host>:4100 HNX_SECRET_GATEWAY_MASTER_KEY=... \
HNX_SECRET_GATEWAY_KEY_CONFORMANCE_THROTTLE=... HNX_SECRET_GATEWAY_KEY_TELEMETRY_READER=... \
  hnx conform run inference --target <copy of modules/gateway/conformance/target.yml>
```

`gateway-limit-throttles` uses up the throttle key's minute: a rerun inside it starts on a used-up key.

## Known limits

- **No `embeddings` feature in the module's target yet**: no embedding backend exists in the new lab, so the target does not check one. Add `embeddings` to `module.yml` and the target (with an `embed_model` role) when a backend exists.
- **The usage file is not rotated** by the gateway. `health` fails past `gateway_usage_max_mb`; export it,
  stop the gateway and move the old file aside. A rotation timer is a later change.
- **Limits are in memory and per process**: a restart (a key rotation, a config change) clears them; two
  gateways would each allow the full budget. The lab runs one.
- **The listen is plain http** on the lab segment. TLS (`-tls-cert`/`-tls-key`) is not wired: it needs a
  certificate source the module does not have yet.
- **The egress to the provider is not enforced by this module** (the container's own network namespace);
  the per-VM firewall is the control (above), and the role refuses any cloud host the site did not allow.
- **A key is revoked by a spec change and a restart**, not live.
