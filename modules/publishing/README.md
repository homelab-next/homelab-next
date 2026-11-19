<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `publishing`: the lab's only egress path for published content

A feature module ([module manifest](../../docs/modules.md), draft), promoted from the fictional
`examples/modules/publishing`. It owns the `publishable-output` interface: every producer offers
items under its own prefix, each with a sidecar that **claims** a TLP, and this module is the one
identity allowed to send anything off the lab. Nothing here names a real host, address or secret value.

| | |
|---|---|
| Role | `publishing_gate` (role interface v1) on the `publisher` host role |
| Code | `homelabnext/publishing` (standard library only), run as `hnx publishing --config <file>` from the runtime release (role `hnx_runtime`) |
| Modes | `stage`, `dry-run`, `live` (default `stage`) |
| Adapters | `pages` (a static-site deploy with a **pinned** wrangler) and `r2-feed` (episode upload and `feed.xml`) |
| Schedule | the fleet unit `publishing-run` (`units/fleet_units.yml`): hourly at :20, as the module's own service user, under the generator's full hardening block |
| Egress | the hosting API and the object store, granted in the overlay (`grants.egress`); none is made in `stage` |
| Credentials | by name, at run time (below); never in the repository, the config or an environment file |

## An item

`<publishable>/<kind>/<id>/`, `kind` being `site` or `podcast`, holding the producer's files and a
`sidecar.json`:

```json
{"tlp": "clear", "producer": "<module>", "sha256s": {"index.html": "<64 hex>"}}
```

A site item is a built site tree. A podcast item is exactly `metadata.json` (`period`, `date`, `title`,
`description`) and `<period>_<date>.mp3`. Only the newest `site` build is the site (older ones are reported
`superseded`); every `podcast` item is processed each run (idempotently).

## The gate

A sidecar's `tlp: clear` is a label, never proof that a gate ran upstream (a producer's podcast path may have none): the gate judges the actual text of **every** file of every item (site files, `metadata.json`, transcripts and show notes beside an episode) and never relaxes a check because the claim says clear. Audio is checked by its sha256 only (it cannot be read as text).

Fails closed: an item that cannot be judged (no sidecar, a symlink, a file the sidecar does not list, an
unknown file type, a non-UTF-8 text file) blocks. For each item:

1. **TLP.** The label is the strictest of the sidecar's claim and every TLP marker in the item's text
   (`homelabnext.tlp_egress`). It must be at or below `tlp_allowed`: `clear`, or `green` for a `community`
   audience with an `access_control`. Amber and red never pass, and an unreadable claim is red.
2. **sha256.** Every file must match the sidecar.
3. **Deny-list** (the site's secret `publishing/deny-list`): one rule per line; `#` comments; `re:<pattern>`
   for a regular expression; anything else is a case-insensitive literal; `!<name>` is an exception (a match
   wholly inside it is excused, e.g. one public host under an otherwise denied domain). A list with no deny
   line is refused. Text is also scanned after HTML-entity decoding.
4. **Secret shapes** (always on): private-key blocks, cloud access key ids, forge and chat tokens, bearer
   tokens, JWTs, `key = <long value>` assignments.
5. **Disclosure posture** (on by default; `posture_rules`): the first four rules of the old pipeline's
   disclosure guard (LL-051: "our estate", "present in the environment", "we run", "affected assets"). The
   count-adjacent rule needs a context window and stays with the producer's own check; internal-name rules
   are the deny-list's job.

A blocked item is **refused and logged**: `state/gate.jsonl` records the rule and the file, never the text
that matched. The run exits 1 and pages once through the notify pair (`Publishing: an item was blocked by the
gate` / `Publishing: the gate passes every item again`), state-diffed, never per run.

## What the gate reads, and what it is

The gate is a literal, **normalised** matcher: every rule runs over the text as written and as a reader
sees it (HTML entities and percent escapes decoded up to three layers, NFKC, zero-width, soft-hyphen and other
format characters removed, look-alike Cyrillic and Greek letters folded to Latin, base64 `data:` URIs decoded),
and over JSON after decoding (keys and string values). It does not run scripts or rebuild strings a page
assembles at run time. It also judges:

* **names**: every file and directory name, the item id and the sidecar's `producer` and `title` (they become
  public URLs or visible fields); a reason names the file's number, never the matched text;
* **binaries by content**: a suffix proves nothing. Magic bytes must match the type (MP3, PNG, JPEG, GIF, WebP,
  ICO, WOFF/WOFF2), a text file may not hold binary, and the text a media file carries is scanned: ID3 frames
  (and the ID3v1 and tail tags), PNG `tEXt`/`iTXt`/`zTXt`/`eXIf` and ancillary chunks, JPEG comment and APPn
  (EXIF, XMP) segments, and every printable run of the other formats. What does not parse is refused;
* **what the adapters generate**: the `feed.xml` a run would write is gated like an item (claim clear) before any
  upload; a feed that does not pass (for example one built from an episode already in the bucket) blocks the run
  and nothing is written;
* **never published**: `sidecar.json`, and anything not in the sidecar. `wrangler.*`, `functions/` and
  `_worker.js` are refused in an item (a deploy configuration is not content).

## A private snapshot is what is published

The producers' directory is group-writable, so a check there proves nothing about the push. Each item is copied
into `state/snapshots/<kind>/<id>-<digest>/` (owned by the module's user, `0700`): every byte is read once with
`O_NOFOLLOW`, hashed as read and written from the same bytes (a symlinked item or kind directory, a symlink and a
hard link are refused), then gated **there**, and only the snapshot is deployed or uploaded (R2 stamps the sha256
of the bytes it sends). The sidecar is not copied. A snapshot is named by its content, so an unchanged item
reuses it; old ones are not deleted by the module (prune `state/snapshots/` by age).

## Modes

* **stage** is what a shadow lane runs (no notification either: no notifier is built): the gate, then each passing item copied to
  `<staging>/<kind>/<id>-<digest12>/` with a `plan.json` (what each adapter would do). **Zero network calls**:
  the transport is one that raises (whatever a caller passes in), and no hosting credential is read.
  Staged directories are built beside and renamed in; nothing is ever removed.
* **dry-run**: the gate, then **reads only** (the bucket listing and the remote feed) through a transport that
  refuses any method but GET and HEAD, and the computed plan. Writes nothing, deploys nothing.
* **live**: the gate, then the pushes. A blocked item is never pushed and does not stop the others.

## The `pages` adapter and the pinned wrangler

The old pipeline ran `npx --yes wrangler@latest pages deploy` every hour: an unpinned supply-chain pull on each
run. Here the version is an exact `X.Y.Z` (`publishing_gate_wrangler_version`, default `4.157.0`, 16 days old
when chosen), installed by the role with `npm ci --ignore-scripts` from a **lockfile pinned by sha256**: the
lockfile lists every package with its integrity hash, so pinning the file pins the whole tree. The site supplies
it (`publishing_gate_wrangler_lock_src` on the control host, `publishing_gate_wrangler_lock_sha256` its hash), the
way the orchestration module takes its binary; it is not committed here because an npm lockfile is a few
hundred long base64 hashes that the repository's leak scan (rightly) cannot tell from keys. Generate it from the
manifest the role renders:

```
mkdir w && cd w && printf '{"name":"hnx-publishing-wrangler","version":"0.0.0","private":true,"description":"Pinned wrangler for the publishing module","dependencies":{"wrangler":"4.157.0"}}\n' > package.json
npm install --package-lock-only --ignore-scripts && sha256sum package-lock.json
```

Enforced at three layers, each tested:

* the role refuses a pin that is not an exact version, a lockfile that does not hash to the pinned sha256 and
  one that does not pin that version; it installs only from it;
* the adapter refuses unless the lockfile's hash, its wrangler entry, the installed package and
  `wrangler --version` all say the pin;
* the argv is the installed binary, never `npx`, never `@latest`, and always `--branch=<production branch>`.

wrangler runs on the node the role verified (`pages.node`, first on `PATH`) with an empty directory of the gate's as its working directory, so it never finds a `wrangler.toml` or `functions/`. A deploy whose tree digest equals the last published one for the project is skipped (idempotent). To bump:
generate a new lockfile, set the version and its sha256 together, run `playbooks/upgrade.yml`.

## The `r2-feed` adapter (the podcast feed)

A port of the old feed builder. Bucket layout: `episodes/<period>_<date>.mp3|.json`, `feed.xml`, `artwork.png`.

* **Additive and idempotent.** The client has no delete. A key that exists with the same bytes is left alone; a
  key that exists with **different** bytes is a conflict and refused (a published key never changes: podcast
  apps cache the enclosure URL). Publishing twice makes no write. New objects are created with
  `If-None-Match: *`, so a race cannot overwrite.
* **`feed.xml`** is replaced only if it still is the version that was read (`If-Match` on its ETag; a lost race is read again once, then failed). It is rebuilt deterministically from the bucket's episodes and written only when it differs from
  the remote one, and **never when it would drop an episode the remote feed carries** (a partial listing cannot
  shrink the feed). An empty feed is refused.
* **Feed state in the bucket is untouched** except by that rule: nothing is renamed, moved or deleted.
* Episodes already in the bucket with no sha256 stamp (from before this module) are compared by size only; the plan reports them as `unverified_by_size_only`. Requests are signed in the module (signature v4, region `auto`; tested against a published vector).

## Credentials (by name, at run time)

| Secret name | Used for | Modes |
|---|---|---|
| `publishing/deny-list` | the deny-list (its content) | all |
| `publishing/cloudflare-api-token` | the Pages deploy | live |
| `publishing/r2-access-key-id`, `publishing/r2-secret-access-key` | the object store | dry-run, live |
| `publishing/notify-token` (optional) | the notify pair | any |

The role writes each as a `0600` file owned by the module's service user under
`/etc/hnx-modules/publishing/credentials/` (a `0700` directory), from the secret store in a `no_log` task. The
run refuses a credential file that is group- or world-readable, missing or empty. Only the credentials the mode
needs are written (stage: the deny-list alone). The account id is configuration, not a credential.

## Published-manifest export

`state/published-manifest.jsonl` (append-only; one record per real publish: adapter, target, item, tree
digest, TLP, files) is the module's data: the export hook copies it out with its sha256, restore verifies the
sha256 and never overwrites a non-empty live manifest.

## What the overlay adds

A selection of `publishing` placed on the publisher host; `grants.egress: {publishing: {publisher: [internet]}}`
(for `dry-run`/`live`); group variables for the mode, `pages_project`, `r2_bucket`, the account id, the feed
identity; the five secrets above. Producers write items into `/var/lib/hnx-modules/publishing/publishable/`.
Start the lab in `stage`; move to `dry-run` to compare the computed feed with the live one, then `live`.

## Not done here

The Direct Upload API as an alternative to wrangler; the old guard's count-adjacent rule; a notify body
beyond item names. The producer side (writing items with their sidecar) is the producer's change.
