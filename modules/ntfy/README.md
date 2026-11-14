<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `ntfy`: the notify provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `notify` slot with [ntfy](https://ntfy.sh), a self-hosted publish and subscribe server. It is a
**service, not a machine**: the guest it runs on is the site's guest file, and the site's selection
places the module's one host role (`server`) on it. Nothing in this directory names a real host,
address, VM id or secret value; those live only in the private overlay.

| | |
|---|---|
| Slot | `notify` (contract `conformance/protocols/notify.py`), stateless |
| Adapter | the shared `homelabnext.conform.adapters.ntfy:make`, feature `fault-injection` |
| Product | ntfy 2.35.0, `docker.io/binwiederhier/ntfy` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 1 vCPU, 512 MB, 4 GB |
| Role | `ntfy` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the credentials, read by name at deploy time) |
| Egress | none |
| Public route | none |

## What the role does

`roles/ntfy` renders one `compose_app` service:

- **The image** is `repository:tag@sha256:digest`. The pin was at least 14 days old when set
  (ntfy 2.35.0, which also closes an anonymous publish into a protected topic through the Matrix
  push gateway on SQLite, the database this module uses); `tools/pin_freshness.py` watches it
  (`role:ntfy/ntfy_image`).
- **Auth is deny-all** (`NTFY_AUTH_DEFAULT_ACCESS=deny-all`). Two accounts are provisioned from the
  environment at every start (ntfy's `auth-users`, `auth-access` and `auth-tokens`; ntfy deletes a
  provisioned account, entry or token the environment no longer names, so what runs is what the
  role says):
  - the **admin** (`ntfy_admin_user`, role `admin`), given only the bcrypt hash of its password;
  - the **publisher** (`ntfy_publisher_user`, role `user`), with **no password** (a well-formed
    bcrypt value made from no password, so it cannot sign in with one) and one **token**, the
    lab's services' credential. Its access list: write-only on `ntfy_publisher_topics` (default
    `*`), and read-write on the scratch topics `<ntfy_scratch_prefix>*` (default `hnxconf-*`),
    where the health hook and the conformance suite read their own messages back. ntfy picks the
    longest matching pattern, so a scratch topic is read-write and every other topic write-only.
- **Nothing calls out.** No upstream (`upstream-base-url`), web push, Firebase, SMTP, phone calls,
  attachments, payments or metrics are configured; the web app is off (`NTFY_WEB_ROOT=disable`),
  and so are sign-up, web login and topic reservations. `behind-proxy` is off: no proxy fronts it.
- **The container** runs as `ntfy_uid:ntfy_gid` (61000, an id no account on the host has), with
  every capability dropped and `no-new-privileges`, a memory limit, bounded logs and a healthcheck
  on `/v1/health`. It listens on 8080 inside; the host publishes it on the guest's own address
  (`ntfy_bind`, default the inventory's `ansible_host`; all interfaces is refused)
  at `ntfy_port` (80, the registry row's port).
- **Secrets** (`secret:ntfy/admin-password-hash`, `secret:ntfy/publisher-token`) reach only the
  compose env_file (`secrets/ntfy.env`, 0600), through `hnx_secret` in `no_log` tasks. Both are
  checked for ntfy's form before the server sees them (a malformed one would stop it at start).

Data lives under the module's data root on the host, `ntfy_data_root`
(`/var/lib/hnx-modules/ntfy`, `root:<ntfy_gid>` 0750, so the container's user can pass through
it): `db/` (`auth.db`, `cache.db`) and `export/` (the exit copy), both the container's user's,
0700. The compose project is `ntfy_dir` (`/opt/compose/ntfy`); its `secrets/ntfy.env` (0600)
holds the admin's hash and the publisher's token.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness (the engine is applied to the guest first), and every credential resolves in its form: the password at least 12 characters, the hash bcrypt of cost 10 or more, the token `tk_` and 29 more |
| `health` | every container of the spec running and healthy; `GET /v1/health` is 200 and `healthy: true`; deny-all is in force: an **anonymous publish and an anonymous read are refused** (401 or 403) and the publisher's token **may not read** a topic outside the scratch prefix (403); the admin signs in with the stored password (`GET /v1/account` as `admin`, so the hash matches it); the publisher's token publishes to a fresh scratch topic and **reads the message back** (`/<topic>/json?poll=1&since=all`); and the **drift check**: `auth.db` holds no account or token the environment does not provision (read-only, as the container's user) |
| `export` | `export/auth.db`, `export/cache.db` and `export/listing.jsonl` (key, size, sha256): each database copied with SQLite's online backup while the server runs, as the container's user (`setpriv` when the play runs as root), so no root-owned file appears beside the server's |
| `backup` | the export, then `compose_app`'s backup manifest (the data root, export included) |
| `restore` | one script, two passes, run as root. **Check** (nothing written): the source directory and every file opened without following a link, each owned by root or the container's user and writable by no one else; `listing.jsonl` naming only the two databases; each a single-link regular file of the listed size and sha256. **Apply** (server stopped): each file copied through the descriptor that was checked into a staging file beside the live one, the staged copy hashed again and integrity-checked, the stale `-wal`/`-shm` removed and the copy renamed into place as the container's user (0600); the server is started again whatever happened |
| `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump (`compose_app` upgrade) |

Two deviations from the role interface table, on purpose: `health` leaves one message in a
scratch topic's cache (it expires after `ntfy_cache_duration`, 12h), and `export` (so `backup`)
writes a new snapshot on every run and reports `changed`.

## Data

| Dataset | Kind | What | Export |
|---|---|---|---|
| `auth` | `state` | `auth.db`: the provisioned accounts, access entries and tokens (all re-created from the secrets at start) | object-tree, by the role's export hook |
| `cache` | `database` | `cache.db`: the messages a subscriber can still poll (transient) | object-tree, by the role's export hook |

Every account, entry and token is provisioned from the secrets at start, so a lost `auth.db` is
rebuilt on the next start; the backup is for the cache and for state ntfy adds itself (its
schema version, the provisioned rows' history), and `auth` is kept (`retention: keep forever`)
because restoring one is how an account the environment does not name would come back: the drift
check catches that.
`notify` is a stateless slot, so the provider entry carries no migration. A VM-level backup
(the guest's `backup:` policy) captures the data root; the export gives it consistent copies.

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file** (`lab/guests/<name>.yml`): a VM, `status: planned` or `live`, baseline `base`,
   with resources covering the footprint (and the docker engine), `firewall_rules` admitting the
   publishers on the registry port and SSH from the deploy host, and a `backup:` policy. The
   guest file's `firewall_rules` render to the **hypervisor's** per-VM firewall, which filters
   before the guest; it is the control for the published port. An nftables or iptables INPUT rule
   **inside** the guest is not: Docker publishes the port through its own NAT and FORWARD chains,
   so a host-firewall baseline in the guest does not see it.
2. **The selection** (`lab/modules.yml`): `hosts.<name>: {guest: guest:<name>}`, and
   `slots.notify: [{provider: ntfy, instance: <instance>, placement: {server: <name>}}]`; every
   other required core slot is a provider or an incumbent (a slot cannot be both).
3. **The registry row** (`lab/services.yml`): `registry/services.yml`'s `notify` row renamed to
   the instance, `host` the guest's name, `version: "2.35.0"`, plus at most the lab's own
   `standing`, `backup_job` and `scope`. `hnx modules check` compares them field by field.
4. **The secrets**, by name, in the secret store: `ntfy/admin-password` (a password),
   `ntfy/admin-password-hash` (`ntfy user hash` of it) and `ntfy/publisher-token`
   (`ntfy token generate`).
5. **The role's variables** (the overlay's `group_vars/mod_ntfy_server.yml`, as the apply path
   passes no generated variables yet): `ntfy_logical_id: <instance>` (required, no default). The
   rendered inventory's `ansible_host` is the guest's IPv4 address, which `ntfy_bind` defaults to;
   set `ntfy_bind` only if the inventory names the host otherwise (a hostname is refused).
6. **Apply**: `docker_engine` on the module group (`mod_ntfy_server`), then the rendered
   `modules.yml` twice (the second `changed=0`), then `checks/ntfy.yml`.
7. **Prove it once against the real server** (the CI run is against a stand-in shaped after ntfy
   2.33): the conformance run below, which exercises the `hnxconf-*` read-write grant under the
   write-only `*`, beside the health hook's own round trip.

## Conformance

`conformance/target.yml` binds the `notify` suite to the shared ntfy adapter with
`token_env: HNX_NOTIFY_TOKEN`: the adapter sends that variable's value as a bearer token, read at
every request. CI runs the suite through this target against the loopback ntfy stand-in, behind a
deny-all front that refuses a request without the token (`tests/modules/test_ntfy_module.py`).
Against the lab's instance:

```sh
HNX_ENDPOINT_NOTIFY=http://<guest>:80 HNX_NOTIFY_TOKEN=<publisher token> \
  hnx conform --root <homelab-next checkout> run notify \
    --target <copy of conformance/target.yml with allow_plaintext: true>
```

`--root` (before `run`) names a source checkout of homelab-next, such as the overlay's pinned
`hnx/`: the conformance suites are executed code and are not in the wheel, so an installed `hnx`
runs a suite only from a checkout it is pointed at (without `--root` it reports "hnx conform needs
a source checkout").

## Known limits

- **Plain HTTP inside the lab.** The token travels unencrypted on the guest's network until the
  edge (generated Caddy, Stage 5) or a TLS listener fronts it; the hypervisor's per-VM firewall
  (the guest file's `firewall_rules`) is the control, not a firewall inside the guest.
  The core `NtfySender` and the adapter refuse a token over `http` to a non-loopback host unless
  `allow_plaintext` is set, so each client opts in explicitly.
- **One shared publisher token** (`holder: granted`), not one per consumer (`holder: consumers`
  needs bind-time issuing, which no provider has yet). Core services that are not modules (the
  status hub, the node notifier) read it by name; no `grants.secrets` entry can name them.
- **An ntfy token can manage its own account**: create more tokens for the publisher
  (`POST /v1/account/token`; never a password, an access entry or another account). A token
  minted that way is not provisioned, so neither a restart nor a rotation of
  `secret:ntfy/publisher-token` removes it. The health hook's drift check fails while one exists
  (or an account the environment does not name); remove it on the guest with
  `docker compose -f <ntfy_dir>/docker-compose.yml exec ntfy ntfy token remove publisher <token>`
  (`ntfy token list` shows them), and do not mint tokens by hand: a token is declared by its
  secret.
- **The container's network is Docker's default bridge**, so `egress: none` is what the server
  is configured to do (no upstream, push, mail or attachment store), not a network rule; an
  outbound rule for the container's traffic (Docker's FORWARD path) is a follow-up.
- **Removal** exports first, takes the container down and deletes `secrets/ntfy.env`; the data
  root (with the export) and the rest of the compose project stay for the operator.
- **No phone or browser push**: those need egress (an upstream or web push), which is off.
