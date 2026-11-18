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
| Secrets | `secret:documents/secret-key`, `secret:documents/admin-password`, `secret:documents/api-token` (administrator), `secret:documents/agent-token` (agents) |
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
- **API tokens: two, on purpose.** The product's export carries accounts but **not** API tokens,
  so after an import every consumer's token is gone. The role therefore owns them, writing each into
  the product's token table on every run (a different value is replaced):
  - `secret:documents/api-token` belongs to the **administrator** (`documents_api_user`, default
    `admin`). **Whoever holds it can delete the whole library**, and the export. It is for operators
    and the health hook (`/api/status/` needs an administrator). **Do not hand it to an agent.**
  - `secret:documents/agent-token` belongs to a **dedicated account** (`documents_agent_user`,
    default `agent`): no password (it cannot sign in to the web UI), not staff, not an administrator,
    no group, and exactly `documents_agent_permissions`: view and change of documents, notes, tags,
    correspondents, document types, storage paths and custom fields. It **cannot delete**
    (`delete_*` is refused by the role). **This is the token the concierge, the research tools and the
    MCP server get**, sent as `Authorization: Token <value>`. An agent that files new documents also
    needs `add_document` (and `add_tag` ... as it creates them): add them to
    `documents_agent_permissions` deliberately. Documents owned by another account need object
    permission as well: an imported library's documents keep their owner. Setting
    `documents_agent_user: ""` removes the account (and its secret).
  The agents' account is created only once the administrator exists, so an empty library about to
  be imported has no account that would collide with the import; run the role again after it.
  Generate the values:

  ```
  python3 -c 'import secrets; print(secrets.token_hex(20))'      # secret:documents/api-token, and again for secret:documents/agent-token (they must differ)
  python3 -c 'import secrets; print(secrets.token_urlsafe(48))'  # secret:documents/secret-key (>= 50 chars of A-Za-z0-9._~+/=-)
  python3 -c 'import secrets; print(secrets.token_urlsafe(24))'  # secret:documents/admin-password (16-128 of A-Za-z0-9._~-)
  ```

  (`token_urlsafe` yields `-` and `_`, which are accepted.) Each is stored in the secret store
  (`secret/data/documents/<name>`, field `value`) and never in git, argv or a log.
- **The inbox.** `consume/` under the data root, mounted at the application's consumption directory;
  files dropped there are consumed. `documents_consumer_recursive` and
  `documents_consumer_subdirs_as_tags` are the two behaviours worth switching.
- **No mail by itself.** `PAPERLESS_EMAIL_TASK_CRON=disable` (`documents_mail_fetch: false`): the
  application never polls a mail account. After an import the role (and the tool with
  `--disable-egress`) lists the imported mail rules and the workflows that send e-mail or call a
  webhook and, by default (`documents_disable_imported_egress`), switches them off; the dump's
  manifest counts them too.
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
| `export` | the product's `document_exporter` into `export/.library`; then **checked** (its records equal the database's, every file is in it and hashes to its checksum, a thumbnail for each document: a bad export fails the hook); archived to `export/library.tar` with `export/listing.jsonl` (key, size, sha256); the exporter keeps `.library` between runs so the next copy is incremental |
| `backup` | the manifest naming the data root |
| `restore` | checks the archive against its listing and refuses a member that leaves the directory, a link or special file, or an archive with no `manifest.json`; refuses a library that already holds a document or an account; extracts to `export/.restoring`, imports with `document_importer`, then compares every tag, correspondent, document type, storage path, custom field, field value and note with the export, each document's relationships (tags, correspondent, type, storage path, title, date) and a thumbnail for each, and hashes every document's files; only then lists (and by default switches off) imported mail rules and e-mail/webhook workflows, removes the staging directory and seeds the tokens. A failure leaves the staging directory |
| `upgrade` | refuses a target not pinned by tag and digest, from another repository, or **older** than the running version (the database is migrated forward on first start and cannot go back), then records the bump. The upgrade playbook **exports and verifies the library first** (the `export` hook's check) and stops there if that fails: the new image is never started on a library without a verified copy |

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

   Before it exports, the dump checks the free space (the library's size, plus a margin) in the
   container's scratch directory and on this host, sweeps scratch directories an earlier interrupted
   dump left (generated 12-hex names only, directly under the scratch directory, idle ten minutes),
   and removes its own scratch directory on SIGTERM and SIGHUP as well as on an error. It runs the
   product's sanity checker on the source and records its findings. The dump is refused unless every document's original and archive copy hashes to the checksum the
   export's own manifest records (md5 or sha256, by length), every thumbnail is present, no member
   is a link or leaves the tree, the counts of the manifest equal the live database's at the end
   (a write during the export is caught), and the source is not vacuous. `dump-manifest.json` records
   the counts, a digest of every document's checksums and `quiescent` (true only when nothing
   changed between the first read and the last).

   **Documents that share a file.** The product allows two documents with the same original (same
   checksum, each with its own notes, tags, owner and field values), and its importer puts no
   constraint on the checksum: it writes every document under its id. The tool therefore identifies
   a document by its **id** through dump, restore and verification, carries every one of them, and
   lists each group that shares a checksum in `duplicate_checksums` (dump manifest and restore
   report) so the operator sees them; nothing is merged or dropped. Whether to delete a duplicate is
   the library owner's decision, on the source or the target, never the migration's. Corruption is
   still caught per document: each file must hash to the checksum its own record carries.
3. **Rehearse**: restore into the empty target (the staging directory is in the container's export
   volume, which is `export/` of the data root):

   ```
   python3 tools/migrate/documents.py restore --ssh <user@target-host> \
     --app-container documents-app-1 --src-dir /usr/src/paperless/src \
     --staging-dir /usr/src/paperless/export --dir <private dir>/dump-1
   ```

   **No downgrade.** An application cannot open what a newer one migrated, so the restore reads the
   source's version (the export's own `metadata.json`, recorded in the dump manifest) and refuses,
   before it writes anything, a source newer than `product.version` of `module.yml` (the version the
   image pin carries), naming both versions; a dump that records no version, or one that does not parse, is refused too (a leading `v` is accepted; a pre-release or build suffix counts as its base version, so `3.5.1-rc1` is 3.5.1).
   `--source-version <image tag>` supplies or confirms it (the newer of the two decides: it can supply a missing version, never lower a recorded one). The fix for
   a refusal is to pin the module to the source's version or newer, never to restore anyway.

   It refuses a target that holds any document or account before it writes, imports, then reads the
   target: the product's exporter is run again **on the target** and its manifest compared with the
   dump's, document by document (by id): checksums, owner, tags, correspondent, document type, storage
   path, custom-field values, notes, title, date and text must be equal by name, and every document must
   have a thumbnail; any difference fails and the target's re-export is kept for inspection. The
   sanity checker runs on the target too: a finding the source did not have fails, one it already had is
   reported. Imported mail rules and e-mail/webhook workflows are listed (`--disable-egress` switches them
   off). Then the counts of documents, tags, correspondents, document types, custom fields, custom field
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

### When a dump stops

- **`the export names auth.user <id>, which it does not hold`** (exit 2): a document, tag,
  correspondent or other object is **owned by an account the product's exporter leaves out**. The
  exporter never exports the internal `consumer` and `AnonymousUser` accounts (nor their settings and
  permissions), so an object owned by one of them points at an account the export does not carry,
  and the import could not satisfy it either. The tool stops rather than drop or reassign the owner
  on its own. Fix it on the **source**, as the library's owner decides: find what that account owns,
  and give it to a real account (the web UI's bulk edit "set owner", or in the application container
  `python3 manage.py shell -c "from documents.models import Document; from django.contrib.auth.models import User; print(list(Document.global_objects.filter(owner__username__in=['consumer', 'AnonymousUser']).values_list('pk', flat=True)))"`
  to list the documents first), or clear the owner, then dump again. Check tags, correspondents,
  document types, storage paths and custom fields the same way if the id still appears.
- **Documents that share a checksum** do not stop a dump: they are carried and listed (above).

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
