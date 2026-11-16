<!-- SPDX-License-Identifier: Apache-2.0 -->
# The automation provider (StackStorm 3.9)

Fills the provisional `automation` slot: **when a workflow pack runs**. An event from the bus or a
timer is matched by a rule, which starts one run of a pinned [workflow pack](../../docs/workflows.md).
Everything a run changes goes through the [broker](../../docs/broker.md); StackStorm holds no
credential for any target. The pack is the one homelab-next renders
([`workflows/stackstorm/`](../../workflows/stackstorm), [docs/stackstorm.md](../../docs/stackstorm.md));
this module **deploys** it, it does not define it.

| | |
|---|---|
| Product | StackStorm 3.9.0, the official container images (`st2api`, `st2auth`, `st2stream`, `st2scheduler`, `st2workflowengine`, `st2actionrunner`, `st2rulesengine`, `st2timersengine`, `st2garbagecollector`, `st2web`), MongoDB 4.4.30, RabbitMQ 3.12.14, Redis 7.2.16 |
| Why containers | StackStorm 3.9 packages target Ubuntu 22.04 and Rocky 9; the lab's base is Debian 13 |
| Runs as | `compose_app`, every container in the module's role slice (`cgroup_parent`), no capability but `st2web`'s four (nginx starts as root), `no-new-privileges`, every image pinned by tag **and** digest |
| Row | `automation` (`impl: stackstorm`), http, port 9101, `auth: own`, **no public route** |
| Status | the hub's existing `poll-stackstorm` reader (`status_sources` on the row; fixture `tests/status/fixtures/stackstorm-executions.json`) |
| Shadow first | every rule ships **disabled** and every pack rule is in **shadow mode** (it records the broker request it would make and sends nothing) |

## What runs where

```
 bus (events) --durable consumers--> hnx-st2-bridge (systemd) --POST /api/v1/webhooks/homelabnext--> st2web :9101
                                                                                                        |
 st2web (nginx: UI, /api/ -> st2api, /auth/ -> st2auth) --> st2api --> RabbitMQ --> rules engine / timers engine
                                                                          |-> scheduler -> workflow engine -> action runner
 action runner --pack virtualenv (CPython 3.11)--> admit / step --shadow: record only; live: ssh -L socket--> broker
 MongoDB (state), Redis (locks only, no persistence)
```

* **`st2web` is the front, and the only published service.** StackStorm's API has no `/api` prefix of
  its own (`/v1/...`); the bridge, the status hub's reader and the registry row all use
  `/api/v1/...`, which is what the web container's nginx maps. The web UI comes with it: it is
  reachable on the guest's address by the zones the site's firewall admits and nowhere else (no edge
  site, no public hostname, no forward-auth in front: StackStorm's own sign-in and API keys are the
  login); the sign-in service is the same port's `/auth/` path. The role's own checks and the event
  bridge reach it on the guest's own address, from the guest itself, so no key leaves the host (the
  bridge's plaintext opt-in is for exactly that).
* **The front resolves its upstreams once, when it starts.** A service behind it that is recreated
  (a new pack release, a changed configuration, an image bump) has a new address, and the front
  answers 503 for it until it is restarted; the role restarts it whenever it recreated anything on
  a running stack, and a first install recreates nothing.
* **Redis holds coordination locks only** (no persistence, no password, no published port).
  MongoDB and RabbitMQ are reached only inside the compose network, with a password each.
* **The pack is mounted read-only** from an immutable release directory of the rendered tree
  (`<data root>/pack-releases/<digest of every file>`); the only edit the role makes is each rule's
  `enabled:` line. A new release is a changed compose spec, which compose recreates by itself.

## Python 3.11 (why the pack's virtualenv is not st2's)

`homelabnext` requires Python 3.11 (`tomllib`, `datetime.UTC`, possessive regex quantifiers); the
st2 3.9 images carry 3.10, whose import fails on all three. So:

1. **once per version** a one-shot run of a pinned image (`uv`) downloads a relocatable CPython
   3.11 into `<data root>/python`, built beside the final directory and renamed into place only when
   the download ran (needs egress, and its checksum is `uv`'s own);
2. `st2.user.conf` sets `[actionrunner] python_binary` to it, so st2's own tool
   (`st2-pack-setup-virtualenv`) builds the pack's virtualenv on 3.11;
3. pip is installed **by hash** (`constraints/bootstrap.txt`), then `files/runtime-compat.txt`: the
   compiled packages the python runner imports (`orjson`, `cryptography`, `pymongo`, `greenlet`,
   ...), the **same versions the st2 images ship**, for 3.11, hash-pinned (st2's virtualenv `.pth`
   exposes st2's own packages to the pack, but its compiled ones are 3.10 builds, and the python
   runner's wrapper dies on `import orjson` without these), then `homelabnext[core]` and its whole
   dependency tree **by hash** (`constraints/ci.txt` of the same commit) with `--ignore-installed`.
4. The health hook proves the result: `import homelabnext.workflows.st2_runtime` and st2's own
   `base_action` in one interpreter that reports 3.11.

**Refreshing the runner's compiled packages** (when the st2 images move): list the versions in the
new image (`pip list --format=freeze` in `st2actionrunner`, the packages with `.so` files:
`find site-packages -name '*.so'`), take each one's `cp311`/`abi3`/pure `x86_64` manylinux wheel
hashes from the package index's JSON API, and regenerate `roles/stackstorm/files/runtime-compat.txt`.

## What the overlay adds

1. **Selection** (`lab/modules.yml`): slot `automation`, provider `stackstorm`, instance
   `automation`, placement `server -> <the guest>`; the guest (VMID = last octet, 133 for the
   cutover) carries the `base` baseline, **docker_engine applied first**, and the `hnx_runtime` role
   when the bridge is on (`stackstorm_hnx_cli`).
2. **Registry row** (`lab/services.yml`) exactly as bound: `host` = the guest, `version: 3.9.0`; the
   overlay copy may add `standing`, `backup_job`, `scope` only. No `public_hostname`, no public route
   (the manifest has none; adding one is refused).
3. **Grants**: `egress.stackstorm.server: [internet]` (the interpreter's download and the package
   index, once per version; a run of the pack reaches nothing but the broker's socket).
4. **group_vars** (every variable is in `roles/stackstorm/defaults/main.yml` with its reason):
   `stackstorm_logical_id: automation`; `stackstorm_network_subnet` (a free private /16 to /29);
   `stackstorm_pack_src` (the checkout's `workflows/stackstorm/`, **the same commit** as the wheel);
   `stackstorm_hnx_wheel`, `stackstorm_hnx_wheel_sha256`, `stackstorm_hnx_constraints`
   (`constraints/ci.txt`), `stackstorm_hnx_bootstrap` (`constraints/bootstrap.txt`);
   `stackstorm_events_endpoint` (`tls://...`), `stackstorm_events_ca_file`,
   `stackstorm_events_api_prefix` (the bridge account's import prefix, `JS.HNX.API` in the lab);
   `stackstorm_broker_host`, `stackstorm_broker_host_key` (the broker host's public key line,
   pinned), `stackstorm_broker_ssh_user`; `stackstorm_enabled_rules` (empty: all off);
   `stackstorm_operator_users` as wanted. The memory budget below is the default; set
   `stackstorm_footprint_memory_mb` and `stackstorm_mem_limit` together.
5. **Firewall**: the guest's own nftables and the per-VM `.fw` (three applies, README of the
   overlay's deploy flow): **9101/tcp** from the status hub and the operator's tooling only; the
   guest's egress for the interpreter and index (the grant above); SSH from the guest to the broker
   host's port. Nothing else on the guest listens.

   **Deploy gate, not advice: the restriction of 9101 must be in force before the first
   `install.yml`.** The port is plain HTTP (`tls: none`) and `/auth/tokens` takes the admin
   password and returns tokens in the clear, so anything that can reach 9101 can sniff or replay
   them. The module cannot check a firewall rule; the operator confirms it (a connection to 9101
   from a host that is not allowed is refused or times out) before deploying, and signs in to
   StackStorm only from the guest itself or through the tailnet, never across the LAN. An `st2web`
   TLS front is a later change; until then this is the written exception.

   On the **broker host**: a **dedicated account** for the forward (`stackstorm_broker_ssh_user`),
   used for nothing else, a member of no group that can reach another socket (never `docker`, never
   the group of any other service's socket), mapped to `profile:workflow-agents` (the binding's
   `actor`) in the broker's manifest. Its `authorized_keys` line is
   `restrict,port-forwarding,permitopen="<the broker socket path>",command="/bin/false" <key>`
   (path form, e.g. `permitopen="/run/hnx-broker/broker.sock"`; needs OpenSSH 8.9 or newer for
   unix-socket targets, and the rehearsal must confirm a `-L` to any other socket is refused).
   `restrict,port-forwarding` alone stops a shell but still lets the key holder (the key is on this
   guest, readable by root and by `hnx-st2-broker`) ask sshd to forward to any socket that account
   can open: `permitopen` is what limits it to the broker's. On the **guest** the forward's
   socket is group-owned by gid **104** (StackStorm's `st2` group, the same gid the containers run
   as): **any local process in gid 104 reaches the broker as the pack's actor**, so no other
   service, user or container on this guest may run with that gid (the role fails if another group
   already owns it). On the **bus**: the bridge's user (a pull durable per `bridge.json` subject,
   `max_deliver: 100`, `ack_wait: 30`; docs/stackstorm.md).
6. **Secrets** (OpenBao KV v2, field `value`; the role refuses a missing one by name, before any
   file is written; every secret is a different value):

   | Secret | How to make it |
   |---|---|
   | `stackstorm/admin-password` | 16-128 of `A-Za-z0-9._~-`: `openssl rand -base64 24 \| tr '+/' '._' \| tr -d '='` |
   | `stackstorm/mongo-root-password`, `stackstorm/mongo-password`, `stackstorm/rabbitmq-password` | 24-128 of the same set (they go into URLs and `st2.user.conf`): `openssl rand -hex 24` |
   | `stackstorm/datastore-key` | the JSON `st2-generate-symmetric-crypto-key --key-path <file>` writes (run it from any `st2api` container); store the file's content |
   | `stackstorm/kv-key` | 32-128 of the same set: `openssl rand -hex 32` (the runtime names its own state entries with it; it is also the one datastore key `stanley` may view) |
   | `stackstorm/webhook-key`, `stackstorm/status-token` | 32-128 of the same set: `openssl rand -hex 32`. **You choose these; the role registers them** (by StackStorm's hash, for `st2bridge` and `st2status`), so there is no `st2 apikey create` step |
   | `stackstorm/events-password` | the bridge's bus user's password |
   | `stackstorm/broker-ssh-key` | an OpenSSH private key (`ssh-keygen -t ed25519`), its public half on the broker host as above |

## Memory budget

One guest also runs other services (133 runs the metrics provider). StackStorm's own production
minimum is 16 GB and 4 cores for a busy install; this budget is for a handful of rules and a few
runs a day, and is all variables:

| Service | Limit | Service | Limit |
|---|---|---|---|
| st2api | 512m | st2rulesengine | 256m |
| st2auth | 192m | st2timersengine | 192m |
| st2stream | 192m | st2garbagecollector | 192m |
| st2scheduler | 256m | st2web | 128m |
| st2workflowengine | 384m | MongoDB | 1024m (cache 0.25 GB) |
| st2actionrunner | 768m | RabbitMQ / Redis | 512m / 128m |

Sum 4.7 GB; the module's footprint (`module.yml`) is **4 CPUs, 6 GB, 30 GB disk**, and the role
refuses limits that add up to more than `stackstorm_footprint_memory_mb`. Garbage collection keeps
executions for 30 days (`stackstorm_retention_days`, 7 or more).

## Rules, shadow mode and going live

`stackstorm_enabled_rules` is empty: **every rule is disabled** (`enabled: false` in the staged
release; the rendered tree ships them enabled, the site decides). Turning one on is a one-line
overlay change (`[on_proposal_validate]`), re-run `install.yml`: the rule runs in the mode the
binding pins, which is `shadow` for all three. The role's shadow gate reads what the runtime
obeys, **every `pinned/*.json`**: a pin that is not `shadow` is refused unless
`stackstorm_allow_live_rules` is set **and** its rule (`on_<pin name>`) is in
`stackstorm_enabled_rules`; `provenance.json` is checked too, but it is not what decides. A shadow run does everything up to the broker, records the request
it would have made (`result: shadow`, its `request_id` and `request_digest`) and sends nothing:
compare it with the timer it replaces (docs/stackstorm.md, "Shadow, then live"). Going live is a
**binding change in git** with a `promotion` entry (a shadow window of at least 7 days and parity
evidence), then a re-render, a new pinned pack and this setting.

The RBAC the role applies (`[rbac] enable`): `st2admin` is `system_admin`. **`stanley`**, the user a
rule runs executions as (no password, no token anyone holds), is **not**: it holds the custom role
`hnx_runner`, one grant, `key_value_pair_view` on `st2kv.system:homelabnext.kv_key`. Why that
one: StackStorm's config loader checks `key_value_pair_view` for the run's user before it decrypts
a datastore reference in a pack config (`st2common` `KeyValueLookup._get_kv`, 3.9.0), and the pack
config's `kv_key` is such a reference. Everything else a run needs is not the datastore: the
runtime keeps its dedupe, coalesce and submitted-request state in a locked file on a volume only
the action runner mounts (`<data root>/state`, `/opt/hnx-state`), because datastore grants
name one key's uid and the runtime's names are HMACs nobody can list in advance, so reaching them
through the datastore API (`action_service.get_value`/`set_value`) needs `system_admin` (the
`admin` role grants the same on keys, so it is no narrower there). `st2status` can list executions
and view the actions of `stackstorm_status_packs`, never start one; `st2bridge` can only post the
pack's webhook; `stackstorm_operator_users` read the pack and its rules. A pack action still runs
as `stanley` with the broker socket and the pack config (`docs/stackstorm.md`, "Who may write the
datastore"), so no command-running action may be executable by anyone who signs in.

## The event bridge and the broker socket

Both are systemd services on the guest, off with `stackstorm_bridge_enabled: false` /
`stackstorm_broker_tunnel_enabled: false`.

* `hnx-st2-bridge` runs `hnx workflows st2 bridge` (docs/stackstorm.md) as its own user against the
  rendered `bridge.json` (the role refuses a `bridge.json` whose key name differs from
  `stackstorm_webhook_key_ref`): durable consumers, ack after a 2xx, poison to the dead-letter
  stream, posting to the web front on the guest's own address. Its secrets are in an owner-only environment file
  under the names the bridge resolves.
* `hnx-st2-broker-tunnel` is `ssh -N -L <socket dir>/broker.sock:<broker socket>` as a service user,
  the broker's own remote-agent path: the broker sees the forwarding `sshd`'s user on its host and
  maps it to the pack's actor. The host key is **pinned** (never trust on first use), the socket
  is group-owned by StackStorm's numeric group (mode 0660), and its directory is created by
  `tmpfiles.d` so a restart of the forward does not invalidate the container's mount. The socket
  inside the action runner is `/run/hnx-broker/broker.sock`, the path the rendered config names (the
  role refuses a pack whose config names another).

## Health, backup, restore, upgrade

* **Health** (read-only but for one no-op execution): every container healthy (the rules engine and
  the timers engine included); the registered pack is the rendered version with exactly the rendered
  rules, enabled only as named, every pack in shadow mode; the pack's runtime imports on 3.11; a
  `core.noop` execution goes API -> scheduler -> action runner to `succeeded` (the equivalent of a
  one-shot local command run, without exposing a shell action); the status key lists executions
  and is refused starting one; the bridge's key is refused reading; the bridge and the forward
  run and the socket is there.
* **Backup / export**: `mongodump` of the `st2` database inside its container (password via a 0600
  config in the container, never an argument), renamed into `export/mongo/st2.archive.gz` when
  complete, with `listing.jsonl` (size, sha256). The previous archive is kept as
  `st2.archive.gz.prev` (one generation; the VM backup is the history) and an empty new one is refused
  before it replaces anything. `mongodump` is consistent per collection only (no `--oplog`: that needs
  a replica set); with the rules disabled nothing writes across collections, so the skew is harmless.
  The pack is git's, the secrets the secret store's, the runtime the wheel's and the runtime's own
  dedupe state is a disposable file under `state/` (not in the dump), so none of them is in it.
* **Restore** (`restore` hook, `stackstorm_restore_source`): the listing is checked first and nothing
  is written until it passes; with the st2 services stopped the archive is staged, hashed again and
  restored with `--drop` for the `st2` database only. **The services start only after a restore that
  succeeded**; if `mongorestore` fails the st2 services stay stopped (MongoDB is up) and the run fails
  naming the archive, so the rules engine never runs on a half-restored database. Health runs after a
  good restore. The dedupe and coalesce windows live in the state file, not the database, so they
  survive a restore as they are.
* **Upgrade**: `upgrade.yml` exports first. The st2 services move **together** (a patch of the
  same minor line, one digest per service: `stackstorm_target_release_tag` +
  `stackstorm_target_release_digests`); a minor or major bump reads StackStorm's release notes first
  (the pack's `stackstorm_version` is `>=3.8.0`). MongoDB, RabbitMQ and Redis move one at a time within
  their `major.minor` (a data format change is a dump and a restore). **MongoDB 4.4 is end of life
  upstream** but is what StackStorm 3.9 supports; the stack is reachable only inside its compose
  network, the database user is limited to its own database and the lab's isolation is the control
  until a StackStorm release supports a newer one.
* **Remove**: exports first, stops the bridge and the forward, removes their units, key and secrets
  file and brings the containers down; the data root is kept.

## Moving invariant R-09 out of experimental

`docs/checklist.md` R-09 ("StackStorm is the when-engine for pinned packs") and the component
`stackstorm` in `tools/experimental.yml` stay as they are in this change: its `until` is "a lab host
runs StackStorm against the rendered pack". **When the module is live on the guest and the health
hook passes**, one change flips it: delete the `stackstorm` entry of `tools/experimental.yml`, remove
`R-09` from `EXPERIMENTAL_INVARIANTS` in the `Makefile`, move `python -m homelabnext.cli workflows st2
check` and the two st2 test files into `make check`/CI's required jobs, and drop the "Experimental"
paragraph of `docs/stackstorm.md`. There is no conformance suite for the automation slot yet
(`conformance/` has none), so the module declares no `conformance/target.yml`.

## Defects found while deploying the rendered pack

The first real run of the rendered pack on StackStorm 3.9.0 found four defects in the renderer, fixed
in the same change as this module (each would have stopped the pack registering or running):
`pack.yaml` had no `email`; a `nexists`/`exists` rule criterion had no `pattern`; the config's secret
key carried `| decrypt_kv` (StackStorm refuses it on a `secret: true` value); and the pack's actions
could not import on the images' Python 3.10 (above).
