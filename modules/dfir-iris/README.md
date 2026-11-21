<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `dfir-iris`: the case-management provider

A provider module (id `dfir-iris`, the product's, as `keycloak` and `ntfy` are: `case-management` is
the slot and the instance) ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that
fills the `case-management` slot with [DFIR-IRIS](https://docs.dfir-iris.org), the incident case
store: alerts, cases, notes, IOCs, assets, tasks and evidence behind a web interface and a REST API.
It is a **service, not a machine**: the guest it runs on is the site's guest file, and the site's
selection places the module's one host role (`server`) on it. Nothing in this directory names a real
host, address, name, VM id or secret value; those live only in the private overlay.

| | |
|---|---|
| Slot | `case-management`, provisional (no contract yet), stateful, migration format `object-tree` |
| Adapter | `homelabnext.conform.adapters.case_management:make` (a read-only probe: the API refuses a caller with no key, answers the key, reports its version) |
| Product | DFIR-IRIS 2.4.29 (`ghcr.io/dfir-iris/iriswebapp_{app,db,nginx}`, one release), RabbitMQ 3.13.7 (alpine); all pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 4 vCPU, 6144 MB, 30 GB |
| Role | `dfir_iris` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the nine secrets, read by name at deploy time) |
| Egress | none |
| Public route | none: HTTPS on the guest's own address, a certificate from the lab's internal CA |

The stage-6 `cases` slot keeps the alert-to-case lifecycle contract
(`conformance/protocols/cases.py`); this module does not claim it. The product's API can be mapped to
that contract later by an adapter and a conformance run; until then `case-management` is the
product's own case store, with the same health and the same export and restore as every other
stateful module.

## What runs

Five containers in the module's slice (`hnx-dfir_iris-server.slice`), none as root, every capability
dropped, `no-new-privileges`:

| Service | Image | Port | Notes |
|---|---|---|---|
| `nginx` | the product's TLS front | 8443, published on the guest's own address | certificate from `secret:dfir-iris/tls-cert` / `tls-key`; the only published port |
| `app` | the app image | 8000 (internal) | gunicorn; creates the schema and the first administrator on an empty database |
| `worker` | the same image | none | celery; modules and pipelines. **Not** given `IRIS_WORKER` (see below) |
| `db` | the product's PostgreSQL 12 image | none | `pgdata/` under the data root, `postgres` (uid 70) |
| `broker` | RabbitMQ | none | the worker's queue; `broker/` under the data root |

The data root is `/var/lib/hnx-modules/dfir-iris/`: `pgdata/`, `broker/`, `files/` (the product's
datastore: uploaded evidence; its report templates; downloads), `tls/` (the certificate files, the
CA) and `export/` (root's) with `export/db/` (the database's).

Measured against the real 2.4.29 images (a fresh instance, the cases of an earlier one restored):
the app runs as an arbitrary user with `cap_drop: ALL`; resident memory is about 200 MB for the app,
60 MB for the database, 130 MB for the broker, 15 MB for the front, and the worker one process per
CPU at about 150 MB each (16 CPUs reached a 1 GB cap, so the default cap is 2g; a 4-vCPU guest
runs four). The 6144 MB footprint is the cap sum with room, not the idle use (about 2 GB).

## What the overlay adds

- the guest and the module's `server` placement (see "Placement" below);
- the instance (`case-management` or the site's name) and the registry row as the module declares
  it, with at most `standing`, `backup_job` and `scope`;
- `dfir_iris_logical_id` (the row's id) and `dfir_iris_hostname` (the internal name the certificate is
  issued for) as group variables; `dfir_iris_admin_user` and `dfir_iris_admin_email` if the defaults
  do not suit;
- firewall rules: 8443 from the named consumers and the analysts' addresses only; 22 from the
  control host; nothing outbound is needed (`egress: none`);
- the nine secrets in the secret store, each named by the module (the first column is the name after the module's own prefix):

| Secret | Form | Notes |
|---|---|---|
| `db-password` | 24 to 128 of `A-Z a-z 0-9 . _ ~ -` | the database role |
| `db-admin-password` | the same | the administrator role the product's set-up creates |
| `session-key` | 16 to 256 printable, no space or quote | **after a migration the source's value** |
| `password-salt` | the same | **after a migration the source's value** (password hashes) |
| `admin-password` | 16 to 128 of `A-Z a-z 0-9 . _ ~ -`, with a lower, an upper, a digit and one of `. _ ~ -` | the first administrator (login `administrator`) |
| `api-key` | 32 to 128 of `A-Z a-z 0-9 . _ ~ -` | **the credential consumers hold**; the role sets the administrator's key to it; granted to each consumer by name (the overlay's grant), never copied |
| `tls-cert`, `tls-key`, `ca` | PEM | certificate chain for `dfir_iris_hostname`, its key, the lab CA |

All nine differ; an unset reference stops the run, naming it, before anything is written (and the
role's `readiness` hook, which the module's preflight runs, says the same).

## Install, converge, health

`ansible-playbook -i <inventory with --selection> modules/dfir-iris/playbooks/install.yml`, or the
apply path. `main` validates the inputs and every credential, renders and starts the five
containers, restarts the front only when a certificate file changed, and waits (up to
`dfir_iris_ready_timeout`, 600 s: the first start creates the schema) for the API to answer its
ping with the key. A second run changes nothing.

**Health** (`tasks_from: health`, read-only): every container running and healthy; the database
answers; then, over HTTPS **verified against `secret:dfir-iris/ca` for the service's name** (curl's
`--resolve` points the name at the guest's address, so the certificate is judged for the name):
`/api/ping` with no key is **refused** (401 or 403, so an open API is a failure), `/api/ping` with
the key answers `pong` (so a key the product does not know is a failure), and `/api/versions`
reports the pinned release (so a container still on an older image is a failure). The key reaches curl
on its standard input as a config line, never in an argument, and the calls run under `no_log`.

**Readiness** (`tasks_from: readiness`, the module's preflight): the container engine, `curl`, and
every credential resolving in its form.

## Fresh first: the first administrator and the API key

On an **empty** database the product creates one administrator (`dfir_iris_admin_user`) with the
password in the secret `admin-password` and ignores that password afterwards: rotating it is done in
the product, and then the secret is updated to match.

**The API key is the secret's, set by the role.** The product would generate a random key for the
first administrator (and a restored database keeps whatever key it held), and the consumers hold the
secret `api-key`. So once the app is up, `main` and `restore` run one `UPDATE` on the product's
`user.api_key` column (by `psql` in the database's container, the statement on its standard input,
under `no_log`: the key is in no argument and in no container's environment) that sets the
administrator's key to the secret's value, changing the row only when it differs. Rotating the key is
therefore rotating the secret and running `main` again. Health proves the key is accepted; a database
with no user of that login changes nothing and health says so.

⚠ The product writes the first administrator's password into the app container's log once, at that
first start (`You can now login with user ... and password >>> ... <<<`). The log is rotated
(3 x 10 MB); anyone who can read `docker logs` on the guest can read it until then. Change the
password in the product and update the secret if the guest's operators are not the administrator.

## Backup, export, restore

**Export** (`tasks_from: export`; also what `remove`, `upgrade` and `backup` do first) writes
`<data root>/export/`, 0700 (it holds password hashes and API keys):

- `db/iris.dump`: `pg_dump -Fc --no-owner --no-acl`, written in the database's container as its own
  user;
- `files.tar`: the datastore, the templates and the downloads;
- `listing.jsonl`: key, size and sha256 of the two (an empty dump is refused).

A snapshot: every run writes a new one. The database is dumped first, then the files, so a file a row
names is in the tar. **For a cutover copy, freeze first** (`docker compose stop nginx worker app`),
export, and start again.

**Backup** (`tasks_from: backup`) runs the export, then the core `compose_app` backup, which names
the data root; the VM's backup job takes the data root whole.

**Restore** (`tasks_from: restore`, `-e dfir_iris_restore_source=<export dir>`): the source is checked
first and nothing is written unless `listing.jsonl` names exactly the two files with the sizes and
sha256 they have. Then, with the front, worker and app stopped, the dump is staged as the
database's user, hashed again, and restored with `pg_restore --clean --if-exists
--single-transaction --exit-on-error`; the files directory is emptied (a delta replaces, it does not
add) and the archive unpacked into it, owned by the app's user; the app is started (it migrates the
schema to the running image) and health is proved. Run again with a newer export for a final delta.

**The restored database brings its own accounts and passwords.** After a restore the secrets
`session-key` and `password-salt` must be the *source instance's*, or the users' passwords do not
match and stored module settings do not decrypt; the administrator's API key is set to the secret
`api-key` (above) and the other users' keys are the source's.

**Restore drill.** Export, restore into a second deployment (or the same one), `health`. The role's
tests run the hooks against a fake docker; against the real 2.4.29 images the same `pg_dump` and
`pg_restore` commands were run by hand (dump, restore over the running database with the app stopped,
start, health green), because an unprivileged workstation cannot own the database's directories.
Run the drill on the real guest before relying on it.

## Carrying in the cases of an earlier instance (optional)

Fresh is the default; the lab's decision (D-3) is a fresh instance. The cases of an earlier instance
*can* come across, and this was proved possible, not done: the archived dump of the old lab's
instance (2.4.27, PostgreSQL 12, custom format, 82 tables) was
restored into this module's 2.4.29 database with `pg_restore --clean --if-exists --no-owner --no-acl
--single-transaction --exit-on-error` and the app started on it: the product ran its migrations
forward and answered healthy. To do it for real:

1. Put the dump at `<dir>/db/iris.dump`, make an empty archive (`tar -cf <dir>/files.tar -T /dev/null`;
   only the database was archived) and the listing
   (`sha256sum`, `stat -c %s`, one JSON object per file with `key`, `size`, `sha256`).
2. Set the secrets `session-key` and `password-salt` to the old instance's values (its `.env`:
   `IRIS_SECRET_KEY`, `IRIS_SECURITY_PASSWORD_SALT`). The administrator's password is the restored
   one; the API key becomes the secret `api-key`.
3. Run the restore on a deployed module; run `health`.

The restore drops and recreates every object in `iris_db`; it is not additive.

## Upgrade

`playbooks/upgrade.yml -e dfir_iris_target_image=<repository:vX.Y.Z@sha256:...>` (or
`dfir_iris_target_nginx_image`, `dfir_iris_target_db_image`, `dfir_iris_target_broker_image`: one per
run). The role refuses a target that is not pinned by tag and digest, is another repository, is
**older** than the running image (a newer IRIS migrates the database forward as it starts and an
older one cannot open it) or, for the broker, is another major version; records it; exports; then
converges with the new pin (set the image in the overlay). Bump the three product images together
and `product.version` and the registry's `version` with them.

## Remove

`playbooks/remove.yml`: export first, stop and remove the containers, delete the env_files. The data
root (with the export) is kept for the operator to archive or delete.

## Notes that cost time elsewhere

- **The worker must not be given `IRIS_WORKER`.** With it set the product skips its start-up and does
  not load the session key and salt, which the worker's module hooks decrypt stored settings with.
  The official compose leaves it unset.
- **PostgreSQL 12** is the product's own image (end of life upstream); it is not reachable from
  anywhere but the project's network. A major bump is a dump and a restore, not an image bump.
- The front is the product's nginx and speaks HTTPS only; there is no plain-http mode.
- Variable names for secrets end in `_login_ref`, `_access_ref`, `_session_key_ref`, `_salt_ref`
  (the role linter refuses a secret-looking variable name carrying a literal default).

## Placement (proposed; the overlay's to decide)

A **dedicated small guest**, `hnx-cases-01`, VMID 138 (its address the VMID on the lab VLAN, the cutover
plan's convention; confirm 138 is free), 4 vCPU, 8 GB, 60 GB on `vmdata`, in the PBS namespace the
other pm205 guests use. Why: evidence uploaded by analysts and an API key for agents are a different
trust and backup profile from the agents' own guest; the module's footprint (4 vCPU, 6144 MB cap
sum, about 2 GB used) does not fit beside OpenProject on `hnx-projects-01` (4 vCPU, 8 GB, which
OpenProject's own footprint nearly fills); and a restore of either does not touch the other. If a
guest is to be saved, `hnx-agents-01` (8 vCPU, 32 GB) has the room and is where the consumers
(triage agents) run, at the price of the evidence and the case database sharing a guest with the
agents. Firewall: 8443 from `hnx-agents-01` and the analysts' addresses; no outbound.
