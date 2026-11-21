<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `intelowl`: the enrichment provider

A provider module (id `intelowl`, the product's, as `keycloak` and `ntfy` are: `enrichment` is the slot
and the instance) that fills the `enrichment` slot with [IntelOwl](https://github.com/intelowlproject/IntelOwl),
an observable-enrichment aggregator: one API in front of many analyzers (DNS, reputation lists,
threat-intelligence feeds). It is a **service, not a machine**: the guest it runs on is the site's guest
file, and the site's selection places the module's one host role (`server`) on it. Nothing in this
directory names a real host, address, public name, VM id or secret value; those live only in the private
overlay.

| | |
|---|---|
| Slot | `enrichment`, provisional (no contract yet), stateful, migration format `object-tree` |
| Adapter | `homelabnext.conform.adapters.enrichment:make` (a read-only probe: the front's liveness, an anonymous API call refused) |
| Product | IntelOwl 6.7.0 (the application image and its web front, one release), PostgreSQL 17.10, Redis 7.2.16, all pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 2 vCPU, 6144 MB, 30 GB |
| Role | `intelowl` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the credentials, read by name at deploy time) |
| Egress | the internet, from the `server` role (the analyzers query public services); the site grants it |
| Public route | none by default; the consumers reach the API over the lab's network |

## What runs

Seven containers in the module's slice (`hnx-intelowl-server.slice`): `uwsgi` (the web worker), `daphne`
(websockets), `beat` (the scheduler), `worker` (the task worker) all of one image; `nginx` (the product's
front, the only published port: the guest's own address on `intelowl_port`, 8080); `postgres` and `redis`
(no published port). Every container drops all capabilities and adds only what it needs (the application
starts as root, hands its log and download directories to its service user and drops to it; the front
binds port 80 and drops to its own user), with `no-new-privileges`.

Data root (`intelowl_data_root`): `pgdata/`, `logs/`, `static/`, `files/` (analyzer downloads, recreated),
`export/` (the exit copy). The compose project (`intelowl_dir`) holds `config/` (the server's settings and
the front's configuration, rendered from templates and mounted read-only) and `secrets/` (0600 env files).

First boot on an empty data root is handled: the application's entrypoint hands its log directory to its
service user BEFORE its management commands create the log files as root, so on a fresh install the
server cannot open them and exits (found live: the dependent containers then refuse to start). `main`
creates the files once before the first start.

## Secrets (by reference; the overlay's secret store holds the values)

| Reference | Used for |
|---|---|
| `secret:intelowl/django-secret` | the application's signing secret; after a migration the SOURCE's own value (its sessions still open) |
| `secret:intelowl/db-password` | the database role's password (only in the containers' env files) |
| `secret:intelowl/admin-password` | the first administrator, read only when `intelowl_admin_bootstrap` (a fresh database) |
| `secret:intelowl/api-token` | the pipeline account's API token (40 letters and digits), **granted** to the consumers: the CTI pipeline's enrichment stage (`cti-agent`) and the agents' enrichment tool read the same reference; the role writes it into the token table of the account `intelowl_api_user`, so no hand-minting and no value in a consumer's file |
| `secret:intelowl/otx-key` | OPTIONAL free-tier OTX key for its two analyzers; read only when `intelowl_otx_key_ref` is set (default empty: the module is keyless) |

The API authenticates with the web framework's token (`Authorization: Token <40 chars>`, one per account,
no expiry). The source's runbook called the pipeline token a "durin" token; the live API does not accept
durin tokens (they are the expiring client tokens of the sign-in flow, one of which lapsed on 2026-08-10
unnoticed), so the role seeds the framework's. To keep the consumers' files unchanged at the cutover, copy
the value the consumers already hold (the source's `authtoken_token` row for the `admin` account) into
the secret store under this reference, by name, never printed.

## The analyzer-name trap (LL-162) and what health verifies

An **unknown analyzer name makes the application answer 400 to the whole submit**; a known analyzer that
does not support the observable's type is dropped silently, and a **disabled** one is dropped silently
too. The CTI pipeline and the agents' tool each carry a list of names per observable class; one bare name
(`MalwareBazaar`, registered as `MalwareBazaar_Get_Observable`) killed every hash enrichment for eleven days.
`intelowl_required_analyzers` (observable class to names, the keyless set both consumers use) is therefore
checked against the RUNNING instance:

- `validate` (every hook): the classes are the product's, every list is non-empty and holds
  registered-name-shaped strings;
- `health`: asks the instance's own model (one `manage.py shell` call) and fails on a name it does not have
  (the 400 case), on a disabled one, and on an observable class that no listed analyzer can run; then reads
  each name through the API with the API token (a 404 is an unknown name, a 401 a bad token).

Do NOT read `disabled` from the API in 6.7.0: its serializer writes `disabled OR health_check_status`, which
is true for every analyzer that is healthy. Health reads the model's flag. A consumer must keep its own
list equal to this one; the consumers' lists are the source of truth for what they ask, this module's is
the contract that an instance can answer it.

Verified live against the real archive (below): `MalwareBazaar` in the list fails health naming it; a
class with no capable analyzer fails naming the class; a request for the bare name is a 400.

## Keyless by default

The default analyzer lists name only keyless analyzers. The archive's database also carries the
operator's free-tier keys that the old instance stored with its plugin configuration (abuse.ch,
Shodan, OTX: 324 non-empty values). A restore CLEARS them (`intelowl_restore_keep_keys: false`, the
default); the analyzers that need a key of their own then fail on that one call and nothing else
(`reported_with_fails`), never a 400. Set `intelowl_otx_key_ref` for OTX (a vault reference the source
already had by name). The abuse.ch analyzers (`ThreatFox`, `MalwareBazaar_Get_Observable`, `Feodo_Tracker`)
want a free `service_api_key`: either restore with `intelowl_restore_keep_keys: true`, or add the key by
hand in the application; this module does not read one by default.

## Migrating in (the old lab's instance)

The source is the archived `pg_dump` custom-format dump
(`tank/archive-oldlab/app/intelowl-core/intelowl/intel_owl_db.pgdump`, PostgreSQL 16.15, 3 MB; the
application tree is archived beside it as `opt-intelowl.tar` and is NOT needed: the images are pinned
here). Its sha256 and the source's counts are what a restore must be given; both are checked, and a source
that is not this product's database (its table of contents lacks the four tables) or is empty is an ERROR,
never a pass:

```
sha256   344083fd70b8e75b525a6cdfa7adc34c9ba6b58b26b44638a08837d87ac78434
counts   jobs 3105, analyzer_configs 219, playbooks 16, users 6    (read from the archive, 2026-11-21)
```

1. `main` with `intelowl_admin_bootstrap: false` (an empty, migrated database; the API token is not seeded
   yet: no account);
2. copy the dump onto the guest (an absolute canonical path), then the `restore` hook with
   `intelowl_restore_dump`, `intelowl_restore_sha256` and `intelowl_restore_expected_counts` as above. It
   stages the dump as the database's user, hashes it again, restores with `pg_restore --clean --if-exists
   --single-transaction --exit-on-error` with the application stopped, counts the four tables and requires
   them to EQUAL the source's before anything starts (otherwise the application is left stopped), starts
   everything (the first start migrates the restored schema to the running image: "No migrations to apply"
   at the same release), clears the stored keys, seeds the API token and runs `health`;
3. `main` again: `changed=0`. The jobs older than `intelowl_old_jobs_retention_days` (14) are flushed by
   the scheduler after the first start, so the job count falls later; the counts are proved BEFORE the
   scheduler runs.

Rehearsed end to end on a workstation against the real archive with real containers: fresh install in
about 90 s, restore counts equal, health green, a second `main` `changed=0`, a real submit
(`Classic_DNS` on an IP: `reported_without_fails`) and the unknown-name 400 reproduced.

## What the overlay adds

The slot instance and selection (`slots.enrichment: [{provider: intelowl, instance: <row>, placement:
{server: <host>}}]`); the registry row bound exactly as `registry/services.yml` (host, `version: 6.7.0`);
the guest (`baseline: [base]`, 2 vCPU, 6 GB, 30 GB); **grants** `egress.intelowl.server: [internet]`; group
variables `intelowl_logical_id`; the five secrets above in the secret store; the firewall (the port to the
consumers' guests only); consumers' grants to read `secret:intelowl/api-token`. A route to the web UI is
optional (`intelowl_web_domain`, a `public_hostname` and its grant).

## Hooks

`main` (render, start, seed), `readiness` (engine + credentials), `health`, `backup` / `export` (a verified
`pg_dump` and a sha256 listing into `export/`), `restore`, `upgrade` (a pinned bump: the application and its
front together with the same tag, never older than the running one, the database a minor bump only; it
exports first and the application migrates on first start).

## Design notes

- The containers hold no secret in their environment: the database password and the application secret are
  in 0600 env files (`compose_app_secret_env`); the admin password and the API token reach a container only
  through the environment of one command, never an argument.
- Redis holds queued tasks only and persists nothing.
- The product's `docker/` tree (a compose file, env files and an `initialize.sh` that wants `sudo` and a
  git checkout, run on the old guest) is replaced by this role; no repository clone happens on the guest.
