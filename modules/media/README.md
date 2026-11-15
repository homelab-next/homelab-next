<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `media`: the media provider

A provider module ([module manifest](../../docs/modules.md), draft, ADR-0027 proposed) that fills
the `media` slot with [Jellyfin](https://jellyfin.org), a self-hosted media server. It is a
**service, not a machine**: the guest is the site's guest file and the site's selection places the
module's one host role (`server`) on it. Nothing here names a real host, address, VM id or the
library's real source; those live in the private overlay.

| | |
|---|---|
| Slot | `media` (provisional: no contract or suite yet), stateful, object-tree export |
| Product | Jellyfin 10.11.11, `docker.io/jellyfin/jellyfin` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 4 vCPU, 8 GB, 40 GB |
| Role | `media` (role interface v1), a wrapper of the core `compose_app` |
| Secrets | none: the accounts are the server's own |
| Egress | `internet` (metadata and artwork lookups, plugin catalogue); grant it in the overlay |
| Public route | the row declares `public_hostname` (the site's value) and `auth: own`; the edge adds **no** forward-auth |

## Decisions that matter

- **`auth: own`, no SSO.** TV apps (Fire TV cubes) cannot do a browser sign-in. They use the
  account's password or **Quick Connect**, which the role keeps on: it seeds `config/system.xml`
  with `QuickConnectAvailable` on a fresh install (never over an existing file), and `health`
  fails when `GET /QuickConnect/Enabled` is not `true`.
- **The library is read-only and the site's.** `media_library_path` (default `/srv/media`) is bind
  mounted read-only at the same path inside the container. The role refuses to start when it is
  not a directory on the guest (a missing mount would be served as an empty library, and the
  server would then remove those items from its database on the next scan). The real source (a
  mount on the guest) is the overlay's. The backup manifest names the data root only.
- **CPU transcoding.** `media_hwaccel` is `none`, the only value accepted: no GPU dependency.
  Hardware transcoding later needs `compose_app` to pass devices through as well.
- **Identity.** The server id is `data/device.txt` in the data directory. A client remembers a
  server by it and by its device tokens: a new id, or a lost device row, and a Fire Cube treats
  the server as a stranger and drops its login. Set `media_expected_server_id` and `health`
  fails if the answering server is any other.

## Migration: `tools/migrate/jellyfin.py`

`python3 tools/migrate/jellyfin.py import SRC DST --map /old=/new` copies an existing config/data
directory (a restored backup, a snapshot of the old guest's volume) into the new one, stopped, and
keeps what clients need: the server id, the server name and settings, users, **devices and their
tokens**, watch state and metadata. It changes only:

- library paths, old prefix to new, in the databases (through SQL, one text value at a time with
  a path boundary: never a byte substitution, which corrupts SQLite's record length prefixes) and
  in the library definitions (`root/`, `config/*.xml`);
- `HardwareAccelerationType` to `none` in `config/encoding.xml` (the old host's GPU settings must
  not follow it; `--no-accel-reset` keeps them);
- Quick Connect on.

It then reads both sides and refuses (non-zero exit, target kept for inspection) when the counts of
users, devices, libraries, items and watch-state rows differ, or the server id is not byte-identical.
`counts DIR` prints the server id and the same counts, read-only, for the freeze-time comparison.
Both schema generations are read (the single database of 10.11 and the earlier `library.db`
layout); a database from an older server is migrated by the server itself on first start, so
upgrade only after the import and an export.

Then restore it into the data root (`config/`, owned by the container's uid) and start the role with
`media_expected_server_id` set to the source's id.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness and valid inputs |
| `health` | every container of the spec running and healthy; `GET /health` is `Healthy`; `GET /System/Info/Public` answers with a server id (the expected one when set); Quick Connect enabled |
| `export` | the server stopped briefly, `export/media-config.tar.gz` (config without cache, logs, transcodes) and `export/listing.jsonl` (size, sha256), the server started again whatever happened |
| `backup` | the manifest naming the data root (not the library, not the cache) |
| `restore` | checks the archive against its listing and refuses a member that leaves the directory or an archive with no `data/device.txt`; stops the server, moves the live config aside (`config.before-restore`), extracts as the container's user, starts again |
| `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump |

`health` calls `/System/Info/Public` (anonymous); `/System/Info` itself needs a signed-in user and
the role signs in as no one.

## Using it in a site

The overlay adds: the selection (`slots.media` provider `media`, an instance named anything but `media` (the module id is a core-name clash), e.g. `media-server`, placement `server`), the
guest (resources and the library mount at `media_library_path`), the registry row exactly as bound
(plus at most `standing`, `backup_job`, `scope`; its `public_hostname` is the site's), the grants
(`egress.media.server: [internet]`, `public_routes`), group variables (`media_library_path`,
`media_gid` of the mount's group, `media_published_url`, `media_expected_server_id` at a cutover)
and the firewall: the edge and the TV clients' zone to the port.
