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
| Static hosting | **preferred**, not required: only `live` pushes anything (see "Modes and the static-hosting slot") |
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
format characters removed, look-alike Cyrillic, Greek, Coptic, Cherokee, Armenian and small-capital letters folded to Latin, variation selectors and bidi
controls removed (a bidi-overridden text is also read reversed), base64 `data:` URIs decoded),
over the text a browser renders (markup removed with an HTML tokeniser, so a name split by `<span>` is whole again and a `>` inside a quoted attribute does not end the tag), with JS and CSS
escapes (`\\x68`, `\\u0068`, `\\68 `) resolved, with combining marks stripped (and the Hangul, Khmer and grapheme-joiner fillers, which draw nothing), and over JSON after decoding
(keys and string values). Decoding runs to a fixed point; text that still changes after 8 layers is blocked. It does not run scripts or rebuild strings a page
assembles at run time. It also judges:

* **names**: every file and directory name, the item id and the sidecar's `producer` and `title` (they become
  public URLs or visible fields); a reason names the file's number, never the matched text;
* **binaries by content**: a suffix proves nothing. The accepted media are MP3, PNG, JPEG and ICO; GIF, WebP
  and fonts are **refused outright** (their bodies are compressed, so their text cannot be read, and a CTI site
  does not need them). Magic bytes must match the type, a text file may not hold binary, and **every printable
  run of the whole file** (ASCII and both UTF-16 orders) is scanned, wherever it sits, plus the structured
  metadata: ID3 frames (compressed, encrypted or unsynchronised frames, and frame types outside text, URL,
  comment, lyrics and picture are refused; an attached picture is read as the PNG or JPEG it is), PNG text,
  `iCCP` and `eXIf` chunks, JPEG comment and APPn (EXIF, XMP) segments. Any byte after a PNG `IEND` or a JPEG
  end marker, an unregistered (private or unknown) PNG chunk, and an ICO holding a PNG are refused, as is
  anything that does not parse. Data hidden inside compressed sample or pixel data is out of scope;
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
reuses it (an extra file in a reused one is refused). Each path component is opened with `O_NOFOLLOW` through
directory file descriptors. **Pruning is part of every run**: the newest `snapshots_keep` (5) per kind, anything
younger than `snapshots_min_age_s` (3600), every item id still in `publishable/` and every id named by the
last 50 manifest lines are kept; only directories the module named and made (a snapshot or `.tmp-` name, a plain
directory directly under the snapshot root, never a link) are removed. Staged items under `staging/` (shadow output) are pruned by age by the same rules (a plain directory directly under the staging root, named like a staged item or a `.tmp-`/`.failed-` leftover, never a link).

## Legacy episodes and the cutover pass criterion

The feed is gated as a whole, so an episode **already public** in the bucket whose metadata fails the current
deny-list or posture rules would block every future feed write, and the module cannot change the bucket.
Fail-closed is the default; the escape hatch is an operator-reviewed list in the configuration
(`publishing_gate_legacy_exceptions`: `{key, sha256}` of each such metadata object). The deny-list and posture
rules skip that object's text (never the item being published: its own key is not excusable) only while its bytes still hash to the reviewed value; **TLP markers and secret
shapes are always enforced**, and a plan reports what was excused (`excused_legacy`).

**A `dry-run` against the real bucket is a cutover pass criterion**: it must finish with the computed feed
accepted (or every legacy blocker listed and reviewed into the exceptions) before `live` is enabled. `stage`
never reads the bucket and does **not** gate the feed: the only new text in a feed is the item's own
`metadata.json`, which stage gates through the same normaliser; the rest (remote, already-public text and the
operator's feed settings) is judged by `dry-run`.

## Modes

* **stage** is what a shadow lane runs (no notification either: no notifier is built): the gate, then each passing item copied to
  `<staging>/<kind>/<id>-<digest12>/` with a `plan.json` (what each adapter would do). **Zero network calls**:
  the transport is one that raises (whatever a caller passes in), and no hosting credential is read.
  Staged directories are built beside and renamed in; nothing is ever removed.
* **dry-run**: the gate, then **reads only** (the bucket listing and the remote feed) through a transport that
  refuses any method but GET and HEAD, and the computed plan. Writes nothing, deploys nothing.
* **live**: the gate, then the pushes. A blocked item is never pushed and does not stop the others.

## Modes and the static-hosting slot

`cap:static-hosting` is a **preference**, not a requirement. `stage` makes no network call at all and
`dry-run` only reads, so a lab with no hosting provider selected (a hosted Pages project is not a host in the
lab, and the slot may have no provider module) still places this module and runs the gate and the staged
would-be publish set. What must not happen is `live` with nowhere to push: the loader's site rules refuse a
selection whose `mode` (its config value, else the manifest default) is `live` while the site selects no
`static-hosting` provider (`features.publishing.config.mode: live pushes through cap:static-hosting ...`).
That rule cannot see the role's own mode, which a site sets as the group_var `publishing_gate_mode`, so the role
**fails closed** as well: `live` needs `publishing_gate_hosting_provider` (the selected provider's logical id)
and validate refuses it without one.
A preference still counts as reaching the slot, so `grants.publish` and the egress rules apply unchanged.
The role itself refuses `live` without the hosting credentials (readiness) and does not install wrangler
(or ask for node and npm) in any other mode.

## Producer lanes: the shadow window's input

A producer may write each lane's items to its own directory (the cti-pipeline module's handoff does:
`<handoff dir>/<lane>/<kind>/<id>/`, same item layout). The overlay names them in
`publishing_gate_lane_sources: [{lane: shadow, dir: <the lane's directory>}]` and puts the service user in the
read group (`publishing_gate_extra_groups`). Each lane source is:

* **always stage-only**, whatever the run's mode: its items are gated by the same policy, then staged under
  `staging/lane-<lane>/<kind>/<id>-<digest12>/` with a `plan.json` that names the lane; nothing is deployed
  or uploaded from it (no transport, no runner, no hosting credential is reachable from it), and it never
  reads or writes the published manifest. There is no `live` key to set: a lane source is refused if it
  has anything but `lane` and `dir`;
* **kept apart**: its own private snapshots (`state/snapshots-<lane>/`) and staging directory, pruned on their
  own, so the same item id in two lanes stays two items, and neither mixes with the publishable area;
* **named everywhere**: the report and the blocked list carry `<lane>:<id>`, the gate log and `plan.json` carry
  `lane`. A lane item the gate blocks pages like any other and runs the same notify pair.

An absent lane directory is an empty lane (nothing handed off yet); one that cannot be read (the service user
is not yet in its read group, a file in its place) is **reported**: `<lane>:unreadable` in the run's `failed`
list and the gate log, and the other sources still run. A lane directory may not be, link to, or nest with
another lane's, `publishable_dir`, `staging_dir`, `state_dir` or `credentials_dir` (compared by real path), and
its items are opened by descriptor chain from the lane directory with `O_NOFOLLOW` (and leaf files with
`O_NONBLOCK`, so a file swapped for a FIFO is refused, never waited on).

The lane's directory is read, never written or pruned, by this module (the producer owns it). Cutover of the
real lane is a deliberate later change (repoint `publishable_dir`), not something a lane source can do.

## Host preconditions

| Needs | Provided by | Check (readiness) |
|---|---|---|
| the `hnx` runtime release (`/opt/hnx/bin/hnx`, which the scheduled run calls) | **no module**: the site applies role `hnx_runtime` (ansible/roles/hnx_runtime, docs/broker.md "Deploying with Ansible") to the guest | the file exists and `hnx publishing --help` exits 0; each failure says how to fix it |
| node 22 or newer, npm, the pinned wrangler | the distribution's nodejs/npm; the role installs wrangler | **only `live` with a Pages project** (the only mode that deploys): node and npm exist, node is 22+; the role installs wrangler from the sha256-pinned lockfile. `stage` and `dry-run` need none of them |
| the pinned lockfile on the control host | the site | when a Pages project is set (the pin is configuration in every mode): it hashes to the pin |

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

wrangler runs on the node the role verified (`pages.node`, first on `PATH`) in a **fresh directory made for that one deploy** under the temporary directory (no `wrangler.toml`, `package.json` or `functions/` above it) and removed afterwards: wrangler 4.157.0 leaves `.wrangler/tmp` in its working directory, so one that outlived a deploy would break the next. A deploy whose tree digest equals the last published one for the project is skipped (idempotent). To bump:
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
identity; the five secrets above. Producers write items into `/var/lib/hnx-modules/publishing/publishable/`, or hand each lane's items to a directory of their own that this module reads as a stage-only lane source (above).
Start the lab in `stage`; move to `dry-run` to compare the computed feed with the live one, then `live`.

### Shadow pass criteria (the `stage` window)

* every scheduled run ends with exit code 0 or a **blocked** item that is understood (a blocked item is the gate
  working; an unexplained one is a defect in a producer or a rule);
* **real episodes pass the gate in `stage`**: MP3 files produced by the real ffmpeg/libmp3lame pipeline (its
  ID3 tag, encoder string and any cover art), not only hand-built fixtures, must come out `ok` with the real
  deny-list; a producer whose real files are refused (an ID3 frame type outside the accepted set, say) is fixed
  or the rule is reviewed, before `live`;
* the staged items and their `plan.json` match what the old pipeline publishes (the cutover plan's parity
  criteria), and `staging/` stays bounded (it is pruned by age: `publishing_gate_staging_keep` newest per kind,
  nothing younger than `publishing_gate_staging_min_age_s`, so a multi-day window keeps its history);
* then the `dry-run` against the real bucket above.

## Not done here

The Direct Upload API as an alternative to wrangler; the old guard's count-adjacent rule; a notify body
beyond item names. The producer side (writing items with their sidecar) is the producer's change.
