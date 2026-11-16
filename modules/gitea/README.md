<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `gitea`: the forge provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `forge` slot with [Gitea](https://about.gitea.com): git hosting over HTTPS and SSH, and the
lab's own container (OCI) and package registry. It is a **service, not a machine**: the guest it
runs on is the site's guest file, and the site's selection places the module's one host role
(`server`) on it. Nothing in this directory names a real host, address, VM id or secret value;
those live only in the private overlay.

| | |
|---|---|
| Slot | `forge` (provisional: no contract yet), stateful, export format `object-tree` |
| Client | the shared `homelabnext.conform.adapters.forge:make` (health, version, repositories, registry challenge) |
| Product | Gitea 28.4.0, `docker.io/gitea/gitea` rootless build, pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 2 vCPU, 2 GB, 20 GB |
| Role | `gitea` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (every credential is read by name at deploy time) |
| Database | SQLite, as the instance it replaces had it (see "Why SQLite") |
| Egress | none |
| Public route | none |

## What the role does

`roles/gitea` renders one `compose_app` service:

- **The image** is `repository:tag@sha256:digest`, the **rootless** build: the application runs as an
  unprivileged user (`gitea_uid:gitea_gid`, 1000:1000) with every capability dropped and
  `no-new-privileges`, and git over SSH is Gitea's built-in server on an unprivileged port, so
  there is no `sshd` in the container. The pin is the version of the instance it carries over
  (28.4.0) and **never older**: a database a newer Gitea has migrated cannot be opened by an older
  one, and the upgrade hook refuses a target below the running version. (The pin was one day old
  when set, because 28.4.0 is the version the old lab runs and nothing newer exists; the 14-day
  cooldown of `tools/pin_freshness.py` reports it as young, which it is.)
- **HTTPS only**, with a certificate from the lab's internal CA (`secret:gitea/tls-cert`, `tls-key`,
  `ca`, written under `<gitea_dir>/tls/`, the key readable by the container's group). The service
  terminates TLS itself; no proxy is needed and none is assumed. `ROOT_URL` is
  `https://<gitea_hostname>[:<gitea_port>]/`, so every clone URL and registry reference carries the
  internal name.
- **Git over SSH** on `gitea_ssh_port` (default 2222), the port the old instance advertised, so
  existing clone URLs and `known_hosts` entries keep working. The host keys are not generated: the
  role writes the three the site gives it (the three `gitea/ssh-host-key-*` secrets, to
  `<gitea_dir>/sshkeys/gitea.<type>`, the names the server reads) and health proves the server
  presents exactly those. On a migration they are the **source's** keys (copied, see "Secrets"), so a
  client that trusts the old host's key trusts the new one. Gitea's SSH server reads
  `SSH_SERVER_HOST_KEYS` as one `gitea.<type>` file per key type; a different file name is
  silently replaced by a freshly generated key, which is why the role fixes the names.
- **Closed by default** (`vars/main.yml`, role vars outrank inventory so a deployment cannot
  loosen them): no sign-up, no anonymous reading (every API and page needs a sign-in), no Actions
  runner, no mail, no OpenID sign-in, no LFS server, no update checker, offline mode. The package
  registry is on.
- **Secrets** (`SECRET_KEY`, `INTERNAL_TOKEN`, the OAuth2 `JWT_SECRET`) reach only the compose
  env_file (`secrets/gitea.env`, 0600) through `hnx_secret` in `no_log` tasks; the plain environment
  holds no secret (a test enforces it). The administrator's password travels in the environment of
  the docker client, named without a value (`docker compose exec -e NAME`), so it is in no command
  line and no log.
- **Data** lives under `gitea_data_root` (`/var/lib/hnx-modules/gitea`): `data/` (mounted as the
  container's `/var/lib/gitea`: repositories, `gitea.db`, avatars, attachments, packages, the
  OAuth2 signing keys), `conf/` (`/etc/gitea`) and `export/`. The layout is the source instance's
  (everything under one application data path), so a dump's `data/` maps onto it name for name.

### Why SQLite

The old instance runs SQLite (a 17 MB database for five repositories, one administrator). A
different engine would turn a copy into a conversion of an irreplaceable store, with new failure
modes, for no benefit at this size; Gitea's own dump and restore carry SQLite faithfully and the
export verifies the result by row counts and a content fingerprint (below). The module does **not**
offer PostgreSQL yet: if the instance outgrows SQLite (concurrent writers: many CI pushes), that is
a follow-up with its own migration, not a setting.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness, the settings, and every credential resolves in its form: the three application secrets 16 to 512 of `A-Z a-z 0-9 . _ ~ -` and different from each other and from the admin password, the certificate and the CA PEM, the key PEM, each SSH host key a private key; a reference with no value is **named** and nothing is rendered |
| `health` | the container running and healthy; `/api/healthz` passes **over HTTPS verified against the lab CA and for the service's name**; an **anonymous read is refused**; the administrator signs in with the secret's password and the service reports the expected version; `/v2/` answers its bearer challenge (the registry is on and closed), and with a pull account its token is accepted; the SSH port answers and presents **exactly the host keys the secrets hold**. Read-only |
| `export` | the service **stopped** (a consistent state), `gitea dump` into `export/dump.zip`, `repos.tsv` (every repository's number of refs, the sha256 of its sorted refs, and its `git fsck` verdict), `manifest.json` (version, row counts and a content fingerprint **read from the dump itself**, repository count) and `listing.jsonl` (key, size, sha256); the previous archive is kept as `dump.zip.prev`; the service is started again whatever happened. It refuses a dump that proves nothing: no account, a failing fsck, or a database that lists a different number of repositories than are on disk |
| `backup` | the export, then `compose_app`'s backup manifest (the data root, export included) |
| `restore` | see "Migrating in" |
| `upgrade` | refuses a target not pinned by tag and digest, from another repository, or **older than the running version**, then records the bump (`compose_app` upgrade); the playbook exports first |

`export` (so `backup`) stops the service for the length of the dump (seconds for a lab this size)
and reports `changed` on every run.

## Secrets

All by reference, in OpenBao KV v2 (`secret/data/<name>`, field `value`):

| Reference | What | New install | **Migration: COPY from the source** |
|---|---|---|---|
| `gitea/secret-key` | `SECRET_KEY` (two-factor seeds, stored credentials) | 64 random chars: `openssl rand -hex 32` | **yes**: `[security] SECRET_KEY` in the source's `app.ini` |
| `gitea/internal-token` | `INTERNAL_TOKEN` (the git hooks' call back into Gitea) | `docker run --rm --entrypoint gitea <image> generate secret INTERNAL_TOKEN` | **yes**: `[security] INTERNAL_TOKEN` |
| `gitea/jwt-secret` | the OAuth2 `JWT_SECRET` | `docker run --rm --entrypoint gitea <image> generate secret JWT_SECRET` | **yes**: `[oauth2] JWT_SECRET` |
| `gitea/admin-password` | the administrator's password | 16+ chars of `A-Z a-z 0-9 . _ ~ -` | the source administrator's password, or set `gitea_admin_password_sync: true` once |
| `gitea/tls-cert`, `tls-key`, `ca` | the certificate (with chain), its key, the lab CA | issued by the lab CA for `gitea_hostname` | no (new) |
| `gitea/ssh-host-key-ed`, `-rsa`, `-ecdsa` | the SSH host keys (private, OpenSSH format) | `ssh-keygen -q -t <type> -N '' -f /dev/stdout`, or to a file, then read it into the store | **yes**: the source's `/data/ssh/ssh_host_<type>_key` |
| `gitea/oidc-client-secret` | the identity provider's client secret | only with `gitea_oidc_enabled` | no |
| `gitea/registry-pull-token` | a `read:package` token of the registry pull account | only with `gitea_registry_pull_user` | no |

**The first three must be the source's on a migration.** Gitea encrypts what it stores with
`SECRET_KEY` (two-factor seeds, OAuth client secrets, access-token verification) and refuses to
decrypt it with another; `INTERNAL_TOKEN` and `JWT_SECRET` are checked or derived from at start. A
restored database under new values opens, and then silently has accounts that cannot use their
second factor and tokens that fail. The values are read from the source instance, by name, into
the secret store and never printed (read the key names first: `sudo docker exec <container> sed -n
'/^\[security\]/,/^\[/p;/^\[oauth2\]/,/^\[/p' <app.ini>` shows the sections; copy the values with a
tool that does not echo them). The SSH host keys are the other carried identity: copied, a client's
`known_hosts` entry for the old address and for the new name verifies the same key.

## The registry (your own images by digest)

Gitea's package registry is on, and its container registry answers on the same HTTPS port at
`/v2/`. The lab builds its own images (the gateway module's image, the orchestration binary's
container) and so far copies `docker save` archives onto guests; with this module a guest pulls
them by digest instead:

```sh
# once, on the build machine (the image name is <hostname>:<port>/<owner>/<name>)
docker login git.<domain>:3443 -u <publisher>        # a token with write:package, not a password
docker push git.<domain>:3443/lab/gateway:1.2.3
docker buildx imagetools inspect git.<domain>:3443/lab/gateway:1.2.3   # note the sha256:...

# in a module's role (pinned like every other image):
gateway_image: "git.<domain>:3443/lab/gateway:1.2.3@sha256:<digest>"
```

**Trust model.** (1) **Transport**: HTTPS with a certificate from the lab CA, verified; each
guest that pulls needs the CA at `/etc/docker/certs.d/<hostname>:<port>/ca.crt` (the baseline can
lay it down from `secret:gitea/ca`); there is no `insecure-registries` entry anywhere. (2)
**Authentication**: the registry needs a sign-in for everything (`REQUIRE_SIGNIN_VIEW`). Guests
use a dedicated **pull account** (a normal user, `registry-puller`, a member of the owning
organisation with read access only) and its `read:package` token, kept as `secret:gitea/registry-pull-token`
and resolved at deploy time like any credential (a module that pulls declares the reference and the
overlay grants it; the token is in no image, no compose file and no log). A **publisher** account with a
`write:package` token is a separate identity on the build machine only. (3) **Integrity**: every
reference a module uses is `repo:tag@sha256:digest`, so what a guest runs is the bytes that were
reviewed whatever the tag later points at, and `compose_app` already refuses an unpinned image. The
digest is the control; the registry is only where the bytes are fetched from. (4) With
`gitea_registry_pull_user` set, health proves the pull account's token is accepted.

The registry serves `docker pull` and `docker push`, so it is reachable by every guest that pulls:
the site's firewall admits those guests to `gitea_port`, and only the build machine may push (a
Gitea permission, not a network one).

## Flows as code: does NiFi's registry client work against Gitea?

NiFi 2.12's flow registry clients are GitHub, GitLab and the NiFi Registry (the three NARs in the
image); there is **no Gitea client**. The GitHub client is a GitHub-API client with a configurable
"GitHub API URL", so the question is whether Gitea's API (`<gitea>/api/v1`) answers what it sends.

**Answer: not usable for flows as code, today.** Tested end to end against a real NiFi 2.12.0 and a
real Gitea 28.4.0 (the client's API URL set to `<gitea>/api/v1`, a personal access token):

- *Reads work, with one condition.* Listing buckets and branches succeeds when the token's user is
  a **collaborator**, and fails (HTTP 409 "Client does not have read access") when it is the
  repository's **owner**: Gitea reports that user's permission as `owner`, which GitHub's API never
  does, and the client's library rejects the unknown value.
- *Writes do not work, even on an existing branch.* Starting version control creates the bucket
  directory and the flow file (`PUT /contents/...` is accepted by Gitea), but NiFi then reads the
  branch ref back, does not recognise Gitea's answer (`GET /git/refs/heads/<name>` is a JSON array in
  Gitea and one object in GitHub), reports "Path or Branch not found" and rolls the file back,
  leaving commit noise (and, on a second branch, a partial write). A **new** branch cannot be
  created at all: the client's `POST /git/refs` is not in Gitea's API.
- There is no property to change that: the GitHub client has only the API URL, owner, repository,
  branch and authentication type.

So do **not** point NiFi's GitHub client at this Gitea. Options, in order of preference: (1) keep
flows in Gitea and commit them from a script or CI using NiFi's flow-definition export (the nifi
module already exports every process group as portable JSON), with NiFi importing from the
checkout; (2) a small GitHub-shaped shim in front of `/api/v1` (rewrite the ref response to an
object, map `owner` to `admin`, handle `POST /git/refs`), which the write path would still need
proving against; (3) the GitHub-hosted repository the nifi module's README already allows (egress
to the internet, a grant). The module keeps an empty `nifi_registry_url` as "no client".

## Migrating in (the old instance, whole)

The source is the old lab's Gitea on `docs-core` (an LXC; reach it as `root@`, see RB-036), a docker
volume `docs-core_gitea_data` of about 435 MB with five repositories (`agent-findings`,
`hermes-plugin`, `hermes-vault`, `homelab-infra`, `vault`) and one administrator. It runs the root
image (an `sshd` inside the container, host keys in `/data/ssh`, SQLite at
`/data/gitea/gitea.db`, repositories at `/data/git/repositories`). The target is this module
**deployed empty first** (a clean install proves the secrets, the certificate and the ports), then
restored:

```sh
# 0. the rehearsal copy (the source keeps running; nothing on it is changed)
T=tools/migrate/gitea.py
SRC="--ssh root@<source> --container docs-core-gitea --exec-user git --config /data/gitea/conf/app.ini \
     --work-dir /data/gitea --repos-root /data/git/repositories --db-path /data/gitea/gitea.db"
python3 $T dump $SRC --allow-live --dir <private dir, not /tmp>/forge-rehearsal      # exit 0
# 1. stage it on the target (a NEW directory under its data root; nothing is overwritten)
TGT="--ssh ansible@<target> --container gitea-gitea-1"
python3 $T stage $TGT --data-root /var/lib/hnx-modules/gitea --dir <that dir> \
     --dest /var/lib/hnx-modules/gitea/export/incoming
# 2. the role's restore (stops the service, places the instance, verifies, starts)
ansible-playbook ... -e gitea_restore_source=/var/lib/hnx-modules/gitea/export/incoming \
     -e '{"hook": "restore"}'      # include_role gitea tasks_from: restore
# 3. verify independently of the restore's own checks
python3 $T verify $TGT --dir <that dir>                                              # exit 0
```

For the **cutover window**: `python3 $T freeze $SRC` (stops the source container: the only write
the tool ever makes to it), `dump` again **without** `--allow-live` (a running source is refused),
`stage`, restore, `verify --require-quiescent` (refuses an export taken from a source that ran), and
only then change DNS and the firewall. `unfreeze` starts the source again if the window is
abandoned. The source stays stopped, not deleted, until the operator signs off.

**What the restore does and checks** (`tasks/restore.yml`, `files/gitea_restore.py`):

1. *Before anything is written*: `listing.jsonl` names exactly the archive, the manifest and
   `repos.tsv`, each file's size and sha256 match, none is a link; the manifest is format 1, of a
   version **not newer** than the image, with accounts and repositories (an empty export is
   refused unless `gitea_restore_allow_empty`), every repository's fsck `ok`, one `repos.tsv` line
   per repository the database lists; and the database inside the archive says what the manifest
   says (counts and fingerprint).
2. *Placing*: with the service stopped, the archive is read member by member (an absolute name,
   `..`, a backslash or a link is refused; only `repos/` and the avatars, attachments, packages,
   signing keys and custom directories of `data/` are taken: the SSH host keys, configuration and
   logs are the role's), written into a stage directory, the database rebuilt from `gitea-db.sql`
   into a new SQLite file (`PRAGMA integrity_check`), the stage given to the container's user, and
   each live path **renamed** to `*.before-restore.<UTC stamp>` (never deleted) and replaced by
   rename. A failure undoes the renames made.
3. *Verifying before the service starts*: the restored database file against the manifest (row
   counts and a per-table content fingerprint: accounts including their password hashes, repository
   rows, public keys, access tokens) and **every repository against `repos.tsv`** (the refs digest
   and a full `git fsck`); zero repositories where the export has some is an error, not a pass. A
   mismatch leaves the service stopped, says where the previous data is, and fails the run.
4. *After*: the service starts, the repositories' hooks are regenerated for this installation's
   paths (the hooks hold the binary's and `app.ini`'s location, which differ between the images),
   and `health` runs.

Run it again with a newer export for the final delta: the instance is the instance again. The
`*.before-restore.*` directories are the operator's to remove once the cutover is signed off; the
role never does.

**Not carried**: Actions data (none exists), the search index (rebuilt), sessions (users sign in
again), and the SSH host keys' files (they come from the secrets). **Pull-mirror and webhook
targets** that name the old address need editing in the repository settings; `ROOT_URL` becomes the
new internal name, so clone URLs change (the new host's SSH port is the same).

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file** (`lab/guests/<name>.yml`): a VM with `docker_engine`, resources covering the
   footprint, `firewall_rules` admitting the clients on `gitea_port` (git over HTTPS and the
   registry: the lab's guests that pull, the build machine) and on `gitea_ssh_port` (git over SSH:
   the operator's workstation, the agents that push), and SSH from the deploy host.
2. **The selection** (`lab/modules.yml`): `slots.forge: [{provider: gitea, instance: forge,
   placement: {server: <host>}}]`.
3. **The registry row** (`lab/services.yml`): `registry/services.yml`'s `forge` row renamed to the
   instance, `host` the guest's name, `version: "28.4.0"`, plus at most `standing`, `backup_job`
   and `scope`. No `public_hostname`: this module has no public route.
4. **DNS**: an internal name for `gitea_hostname`; the certificate must name it.
5. **The role's variables** (`group_vars/mod_gitea_server.yml`): `gitea_logical_id`,
   `gitea_hostname` (required, no default); `gitea_admin_user` (the source's administrator on a
   migration); optionally `gitea_oidc_*` and `gitea_registry_pull_user`.
6. **Apply**: `docker_engine` on the module group, then the rendered `modules.yml` twice (the
   second `changed=0`), then health.

### OpenID Connect sign-in (optional)

`gitea_oidc_enabled: true` with `gitea_oidc_issuer_url`, `gitea_oidc_client_id` and
`secret:gitea/oidc-client-secret` creates (or updates) an authentication source named
`gitea_oidc_name` through Gitea's own `gitea admin auth add-oauth`, the secret passed in the
docker client's environment. The issuer's certificate is verified against the lab CA
(`SSL_CERT_FILE`, set only then). Local accounts stay; automatic registration is **off** (an
administrator creates or links the account), so an OIDC identity is never an unvetted account. The
Keycloak client is a confidential client with the redirect URI
`https://<gitea_hostname>:<gitea_port>/user/oauth2/<gitea_oidc_name>/callback`.

## Tests and tooling

`tests/modules/test_forge_module.py` (manifest, row, pins, overlay, lint),
`tests/roles/test_forge_role.py` (render, refusals, started path, export, restore, upgrade, against
a fake docker), `tests/roles/test_forge_files.py` (the helper and the restore script on real
archives), `tools/tests/test_migrate_gitea.py` (the migration tool against a fake host) and
`tests/conform/test_forge_adapter.py`. The role, the export, the restore, the hooks and the tool
were also run against a **real** Gitea 28.4.0 container (a deployment, a second deployment
restored from the first's export, a push after the restore, the tool's dump and verify).

## Known limits

- **One SQLite database, one instance**: no high availability; the backup is the export.
- **The export stops the service** briefly; do not run it from a scheduler more often than the
  lab can tolerate a few seconds of refused pushes.
- **The container's network is Docker's default bridge**, so `egress: none` is what the service
  is configured to do (offline mode, no mailer, no update check, no Actions), not a network rule;
  webhooks and pull mirrors can still be configured by an administrator and then call out.
- **No Postgres, no LFS, no Actions runner**: each is a separate decision with its own module work.
- **Gravatar** is a database setting in this version (site administration), carried by a restore;
  turn it off there if the source had it on.
- **The old instance's `latest` image** floated; this module pins by digest. A source on a version
  *newer* than the pin is refused by the restore (bump the pin first).
