<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `documents`: the document library

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `documents` slot with [Paperless-ngx](https://docs.paperless-ngx.com), a self-hosted document
management system: documents are consumed (from the inbox or the API), OCRed, filed under
correspondents, document types, tags, storage paths and custom fields, searched, and read back
through a REST API. It is a **service, not a machine**: the guest is the site's guest file and the
site's selection places the module's one host role (`server`) on it. Nothing here names a real
host, address, VM id or domain; those live in the private overlay.

| | |
|---|---|
| Slot | `documents` (provisional: no contract or suite yet), stateful, object-tree export |
| Product | Paperless-ngx 3.4.2, `ghcr.io/paperless-ngx/paperless-ngx` pinned by tag and digest; Redis 7.2.16 as its broker (the pin the automation module also uses) |
| Host role | `server`: kind `vm`, baseline `base`, footprint 2 vCPU, 3 GB, 20 GB |
| Role | `documents` (role interface v1), a wrapper of the core `compose_app` |
| Secrets | `secret:documents/secret-key`, `secret:documents/admin-password`, `secret:documents/api-token` |
| Egress | none: OCR is local, nothing is fetched |
| Public route | **none**. The row declares no `public_hostname`; people reach the web UI and agents the API over the lab's network |

## Decisions that matter

- **SQLite, not Postgres.** The library this module was written for (about 1,500 documents, one
  writer) already ran on SQLite; the database is one file in `data/`, backed up with the data root
  and carried by the export. A server database would add a container, a password and a dump format
  for no gain at this size. The product's exporter and importer are database-neutral, so moving
  to Postgres later is an export, a redeploy with a different engine and an import. (Heavy concurrent
  consumption is the case SQLite serves badly: raise `documents_task_workers` only with a server database.)
- **One application container.** The image runs the web server, the task worker, the consumer and
  the scheduler as processes of one container; `broker` (Redis) is the only other container. The
  broker is unauthenticated and publishes no port: only the application's project network reaches it.
- **Non-root.** The application runs as `documents_app_uid` (the image supports `user:`), with every
  capability dropped. The one thing a non-root start cannot do is install OCR languages, so
  `documents_ocr_languages` is checked against the languages the image ships (`deu eng fra ita spa`).
- **No public route.** `auth: own` (local accounts and API tokens), no `public_hostname`, no
  forward-auth. A site that wants a route adds the `public_hostname`, the grant and `documents_url`.
- **API token.** The product's export carries accounts but **not** API tokens, so after an import
  every consumer's token is gone. The role therefore owns one: `secret:documents/api-token`
  (exactly 40 lowercase hex characters) is written into the product's token table for
  `documents_api_user` (default `admin`, which must be an administrator) on every run, replacing a
  different token. Consumers (the concierge, the research tools, the MCP server) get the same value
  from the secret store and send `Authorization: Token <value>`. Generate it and the other two:

  ```
  python3 -c 'import secrets; print(secrets.token_hex(20))'      # secret:documents/api-token
  python3 -c 'import secrets; print(secrets.token_urlsafe(48))'  # secret:documents/secret-key (>= 50 chars of A-Za-z0-9._~+/=-)
  python3 -c 'import secrets; print(secrets.token_urlsafe(24))'  # secret:documents/admin-password (16-128 of A-Za-z0-9._~-)
  ```

  (`token_urlsafe` yields `-` and `_`, which are accepted.) Each is stored in the secret store
  (`secret/data/documents/<name>`, field `value`) and never in git, argv or a log.
- **The inbox.** `consume/` under the data root, mounted at the application's consumption directory;
  files dropped there are consumed. `documents_consumer_recursive` and
  `documents_consumer_subdirs_as_tags` are the two behaviours worth switching.
- **Nothing from the old gateway.** The previous instance pointed the product's AI features at a
  gateway of the old lab. They are off here; `documents_extra_env` sets any other `PAPERLESS_*`
  setting that is neither a secret nor one the role owns.

## Data root layout

```
<documents_data_root>/                 (default /var/lib/hnx-modules/documents)
  data/        the database (db.sqlite3), the search index, the classifier, logs      app uid, 0700
  media/       documents/{originals,archive,thumbnails}                               app uid, 0700
  consume/     the inbox                                                              app uid, 0770
  export/      library.tar + listing.jsonl (the exit copy), .library/ (exporter cache) app uid, 0700
  broker/      the broker's snapshot                                                  broker uid, 0700
```

The compose project is under `documents_dir` (default `/opt/compose/documents`); the two secrets
the containers read live in `secrets/app.env` (0600), never in `docker-compose.yml`.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness, valid inputs, every secret resolving in its form (a missing one is named, nothing is rendered) |
| `health` | both containers running and healthy; the sign-in page answers 200; an **anonymous** read of `/api/documents/` is refused (401 or 403); with the API token the list answers and holds at least `documents_expected_min_documents`; `/api/status/` says the database is OK with no migration pending and the broker is OK |
| `export` | the product's `document_exporter` into `export/.library`, archived to `export/library.tar` with `export/listing.jsonl` (key, size, sha256); the exporter keeps `.library` between runs so the next copy is incremental |
| `backup` | the manifest naming the data root |
| `restore` | checks the archive against its listing and refuses a member that leaves the directory, a link or special file, or an archive with no `manifest.json`; refuses a library that already holds a document or an account; extracts to `export/.restoring`, imports with `document_importer`, then compares the imported records with the database and hashes every document's files against the export's checksums; only then removes the staging directory and seeds the API token. A failure leaves the staging directory |
| `upgrade` | refuses a target not pinned by tag and digest, from another repository, or **older** than the running version (the database is migrated forward on first start and cannot go back), then records the bump |

The exporter and importer are the product's own (`document_exporter`, `document_importer`): they
carry documents, archive copies, thumbnails, tags, correspondents, document types, storage paths,
custom fields and their values, notes, saved views, workflows, mail rules, share links and accounts
consistently, which a copy of the files and the database would not guarantee. **The export holds every
account's password hash and any mail account's password in plain text**: it is written 0600 into a 0700
directory, and a copy of it leaves the host only through the backup job.

## Migrating in: `tools/migrate/documents.py`

The tool dumps a running instance over ssh with the product's exporter, streams the result into a
private directory, proves it, and restores it into an **empty** instance with the importer, then proves the
copy. It is generic: nothing in it names a host, a path of the product or a lab; the endpoints are
command-line arguments.

1. **Deploy the target empty and unseeded.** `documents_admin_bootstrap: false` (the import brings
   its accounts and the importer is not a merge, so a pre-made administrator would be a conflict),
   `documents_expected_min_documents: 0` for now. `main` reports that the API-token account does not
   exist yet; that is expected.
2. **Dump the source** (read-only on its data; its one write is a scratch directory inside the
   container, removed afterwards). The old instance runs as root, so its commands run as the
   product's own account:

   ```
   python3 tools/migrate/documents.py dump --ssh <user@source-host> \
     --app-container <source app container> --src-dir /usr/src/paperless/src --exec-user paperless \
     --dir <private dir>/dump-1
   ```

   The dump is refused unless every document's original and archive copy hashes to the checksum the
   export's own manifest records (md5 or sha256, by length), every thumbnail is present, no member
   is a link or leaves the tree, the counts of the manifest equal the live database's at the end
   (a write during the export is caught), and the source is not vacuous. `dump-manifest.json` records
   the counts, a digest of every document's checksums and `quiescent` (true only when nothing
   changed between the first read and the last).
3. **Rehearse**: restore into the empty target (the staging directory is in the container's export
   volume, which is `export/` of the data root):

   ```
   python3 tools/migrate/documents.py restore --ssh <user@target-host> \
     --app-container documents-app-1 --src-dir /usr/src/paperless/src \
     --staging-dir /usr/src/paperless/export --dir <private dir>/dump-1
   ```

   It refuses a target that holds any document or account before it writes, imports, then reads the
   target: the counts of documents, tags, correspondents, document types, custom fields, custom field
   values, notes, storage paths and accounts equal the dump's, the checksum of **every file on disk**
   equals what the export recorded, and a run that checked nothing is an error. Then run the
   role again (`main`, `documents_expected_min_documents` = the count, `documents_admin_bootstrap`
   still false): it seeds the API token and `health` proves the library answers with at least that many documents.
4. **The final copy** (cutover window): disable every writer of the source (the fetcher timer, the
   agents that file documents), run `counts` on the source and keep its output, `dump` again into a new
   directory, then restore into a **new empty** target (move the rehearsal's data root aside; never
   delete it in the window) with `--expect-counts @counts.json --require-quiescent`, and `stop` the
   source (`stop --container <app> --container <broker>`); it stays stopped until the operator signs
   off, and `start` undoes it.
5. Repoint the consumers (they keep the same token value: it is the secret's), and keep the source's
   export and the dump until sign-off.

A rehearsal that passes proves the **tool and the target**; it does not prove the final data: the
final copy is verified the same way, on its own.

## Restore drill

Restoring from this module's own export (`export/library.tar`) is the role's `restore` hook: deploy
empty and unseeded as above, then run it with `documents_restore_source` = the directory holding
`library.tar` and `listing.jsonl`. Drill it on a scratch guest from a real export before relying on a backup.

## Using it in a site

The overlay adds: the selection (`slots.documents` provider `documents`, an instance named anything
but `documents` (the module id is a core-name clash), e.g. `docs-library`, placement `server`), the
guest (resources; the data root on a disk with room for the library and its export, about three times
the originals), the registry row exactly as bound (plus at most `standing`, `backup_job`, `scope`),
group variables (`documents_ocr_languages`, `documents_timezone`, `documents_expected_min_documents`
at a cutover, `documents_admin_bootstrap` false for a migration), the three secrets in the secret
store and the firewall: the consumers' addresses (the agents that read the API, the people who open the
UI) to the port, nothing else. There is no egress grant and no public route to make.
