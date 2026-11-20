<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `freshrss`: the feed reader

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `feed-reader` slot with [FreshRSS](https://freshrss.org), a self-hosted RSS and Atom aggregator.
Feeds are subscribed per account, refreshed on a schedule, read in the web UI, and read back by
programs through the Fever and Google Reader APIs. It is a **service, not a machine**: the guest is
the site's guest file and the site's selection places the module's one host role (`server`) on it.
Nothing here names a real host, address, VM id, account or domain; those live in the private overlay.

| | |
|---|---|
| Slot | `feed-reader` (provisional: no contract or suite yet), stateful, object-tree export |
| Product | FreshRSS 1.30.4, `docker.io/freshrss/freshrss` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 1 vCPU, 1 GB, 10 GB |
| Role | `freshrss` (role interface v1), a wrapper of the core `compose_app` |
| Secrets | `secret:freshrss/admin-password`, optionally `secret:freshrss/admin-api-password`; every other account's **name**, **API password** and optional web password are references the site names (below) |
| Egress | the internet: the feeds' own sites, for the scheduled refresh and when a feed list is subscribed |
| Public route | **none**. The row declares no `public_hostname`; people and programs reach it over the lab's network |

## Decisions that matter

- **SQLite, not a server database.** A few accounts and a few hundred feeds are one writer. The
  database is one file per account in `data/users/<account>/`; the product's per-account export and
  import are database-neutral, so a later move to a server database is an export, a redeploy and an
  import.
- **One container, with the image's own cron.** `CRON_MIN` (`freshrss_cron_minutes`, default two
  runs an hour) makes the entrypoint install the image's crontab, which runs the product's refresh
  script as the web server's user. There is no timer on the guest and no second container.
- **The API is on for the whole site and a password per account.** The product has one site-wide
  switch (`--api-enabled`, set at install) and one *API password* per account, used by both the
  Fever API (`/api/fever.php`, key = `md5("<name>:<API password>")`) and the Google Reader API
  (`/api/greader.php`). An account with no API password has no API. An account with no web
  password has no web sign-in, which is what a feed consumer wants: it can read and mark entries
  through the API and cannot sign in to the UI.
- **Accounts come from secrets, never from values.** `freshrss_admin_user` is the administrator (the
  product's default user). Every other account is one entry of `freshrss_users`:

  ```yaml
  freshrss_users:
    - name_ref: secret:<ns>/freshrss-username              # the account's NAME is a secret too
      api_password_ref: secret:<ns>/freshrss-api-password
      # password_ref: secret:<ns>/...                      # optional web password; omit for API-only
      # opml: true                                         # default: subscribe the feed list
  ```

  Names, passwords and the md5 key are read at deploy time by `lookup('hnx_secret', ...)` and handed
  to the container in the environment of one `docker compose exec` command (`no_log`); they are
  never in a file the role writes and never logged. They are **not** hidden from local users on the
  guest, though: Ansible prefixes the task's `environment:` onto the remote `sh -c` line, and the
  product's own tool takes a password as an option, so for the instant each command runs a password
  is visible in the process list to any local user of the guest (as with the forge module's
  bootstrap). Keep the guest's local users to the operator. A second run is `changed=0`: an account that
  exists is checked against its stored hashes and updated only when a password differs.
  The role refuses a reference with no value in the secret store, naming it, before anything is
  rendered; refuses a name or password of the wrong form; and refuses two accounts with one name or
  one password.
- **One feed list, subscribed once per list, for every account that asks.** `freshrss_opml_src` is a
  path on the **control host** and `freshrss_opml_sha256` its digest; the role reads the file there,
  refuses anything but exactly that content (a regular file, never a link, at most 8 MiB, with at
  least one feed address), copies it to `import/feeds.opml` and verifies the copy. Each account with
  `opml: true` (and the administrator with `freshrss_admin_import_opml`) is subscribed through the
  product's importer, which skips a feed that is already there. A marker (`hnx-opml.sha256` beside
  the account's data) holds the list's digest, so a second run does no network work and an account
  that unsubscribed from a feed is not made to resubscribe. After the import the account must hold
  at least as many feeds as the list has distinct addresses (less `freshrss_opml_tolerance`): zero
  or too few is an **error**, not a pass. Two accounts given the same list carry the same
  subscriptions and categories (read state is per account).
- **The image runs as root, so the container is narrowed another way.** Apache and cron drop to the
  web server's user themselves, and the entrypoint changes ownership and the time zone. So the
  container keeps six capabilities (`CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID`,
  `NET_BIND_SERVICE`) with every other dropped, `no-new-privileges`, a memory limit, the module's
  slice, and the data directories mounted from the data root. This was checked against the pinned
  image: install, the accounts, the import, the refresh script's `su` and the APIs all run with those
  six and no more.
- **Health checks the API per account.** The sign-in page answers 200; a Fever call with a key that
  is no account's is refused (`auth: 0`); every account with an API password is accepted by the Fever
  API (`auth: 1`) and signed in by the Google Reader API (an `Auth=` token); every account that
  subscribed the list holds enough feeds. Read-only.

## Data root layout

`freshrss_data_root` (default `/var/lib/hnx-modules/freshrss`):

| Path | Owner | What |
|---|---|---|
| `data/` | the web server's user (uid 33) | the product's data: `config.php`, `users/<account>/` (database, configuration, the opml marker) |
| `import/` | root, group 33, 0750 | `feeds.opml`, the pinned list, mounted read-only |
| `export/` | uid 33, 0700 | `latest/` (the exit copy), `.new` and `.restoring` while a run is under way |

## Hooks

| Hook | What it does |
|---|---|
| `readiness` | the container engine, the inputs, every credential resolves in its form, the feed list is the pinned one |
| `health` | as above; read-only |
| `backup` | writes `backup-manifest.json` naming the data root (see "Backup and restore") |
| `export` | every account's SQLite export and OPML, a manifest and a sha256 listing, built in `export/.new` and renamed into `export/latest` only when every account's copy is whole |
| `restore` | checks an export, then imports each account into an **empty** account and compares counts |
| `upgrade` | validates a pinned bump (same repository, tag and digest, the same or a newer version) and records it |

## Backup and restore

The data root is the unit of backup: the guest's backup copies it while the service runs. The
databases are SQLite files, so that copy is crash-consistent and SQLite recovers from it. The
**consistent** copy is `export/latest`: the product's own export, made through the running
application, so no stop. The upgrade and remove playbooks refresh it first; refresh it by hand
before a copy that must not depend on recovery:

```
ansible-playbook -i <inventory> <a play that includes role freshrss, tasks_from export>
```

**Restore drill** (into an empty reader): deploy the module with `freshrss_opml_src` empty (the list
would subscribe the accounts first and the importer is not a merge), then run the `restore` hook with
`freshrss_restore_source` set to the copy's directory. The role refuses a copy that is not exactly
what its `listing.jsonl` says, refuses an account that already holds a feed or an entry (it names no
value and moves nothing), creates the accounts from the secrets (the export carries no password),
imports each account, and compares its feeds, categories, read, unread and favourite counts with the
manifest. A failure leaves the staged file in `export/.restoring` for inspection. An account in the
copy that the site's `freshrss_users` no longer names stops the run.

## Migrating in from the old lab

The old reader is the FreshRSS container on the old lab's `utility-apps` guest
(`dev/architecture.md` there, section 6: container `utility-apps-freshrss`, port 8084). Only the
**feed list** moves: the 27 thousand old entries are regenerable from the feeds and no read state is
carried. Read-only on the old side; run as the web server's user (`-u www-data`: the product writes
a log file when it runs, and a root-owned one would break the old instance).

1. Name the account whose subscriptions are the list (the one the CTI ingest signs in with;
   `FRESHRSS_USERNAME` in that app's `.env`, read by name, never printed):

   ```
   ssh <ansible>@<utility-apps> 'sudo -n docker exec -u www-data utility-apps-freshrss php cli/list-users.php'
   ```

2. Export it (stdout only; nothing is written on the old guest):

   ```
   ssh <ansible>@<utility-apps> 'sudo -n docker exec -u www-data utility-apps-freshrss php cli/export-opml-for-user.php --user <the account>' > feeds.opml
   ```

3. Check it before it is pinned: `grep -c -i 'xmlurl=' feeds.opml` should be the old reader's feed
   count (259 at the last inventory), and `python3 -c 'import sys, xml.dom.minidom as m; m.parse(sys.argv[1])' feeds.opml`
   must parse. Read the categories it carries: the CTI ingest maps feeds to its internal categories by
   **category title**, so a title changed here changes the pipeline's mapping.
4. `sha256sum feeds.opml`, keep the file on the control host outside the repository, and set
   `freshrss_opml_src` and `freshrss_opml_sha256` in the site's group variables.
5. Deploy. Every account with `opml: true` is subscribed with the same list; `health` then proves
   the counts. The first subscription reads each new feed's page and icon, so for a couple of
   hundred feeds it takes a few minutes per account (`freshrss_import_timeout`).

## Using it in a site

- Place the `server` host role on a guest whose baseline is `base` (docker_engine is applied first).
- Bind the registry row `feed-reader` to the instance name, the guest and the product version
  (`registry/services.yml`); add `public_hostname` and its grant only if a route is wanted, and then
  set `freshrss_base_url` to that name.
- Grant `egress.freshrss.server: [internet]`.
- Open the port (`freshrss_port`, 8084) to the named consumers only, in the hypervisor's per-VM
  firewall and the guest's own.
- Set `freshrss_logical_id`, the accounts, the feed list, and seed the secrets before the deploy.
- A consumer (a pipeline that reads feeds) is an account here, named by the consumer's own secrets:
  it signs in with `md5("<name>:<API password>")` to `/api/fever.php?api`, or with its name and API
  password to `/api/greader.php/accounts/ClientLogin`. A consumer that marks entries read consumes
  them for that account, so two consumers (a live and a shadow one) need two accounts.
