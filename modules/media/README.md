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
| Host role | `server`: kind `vm`, baseline `base`, footprint 4 vCPU, 16 GB, 40 GB |
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
  mounted read-only at the same path inside the container. The role proves the library is really
  there before the container starts and again in `health` and `readiness`: the path must be a mount
  point (`mountpoint -q`) **or** hold the marker file `media_library_marker` (default
  `.hnx-media-library`), which the operator places on the library itself. An unmounted mount point
  is an existing, empty directory, so "is a directory" is not enough: the server would start on it
  and remove every item on its next scan. Emptying or unmounting the library turns health red. The
  real source (a mount on the guest) is the overlay's. Also turn off, in each library's options,
  the removal of missing items; the importer does not change library options. The backup manifest
  names the data root only.
- **CPU transcoding.** `media_hwaccel` is `none`, the only value accepted: no GPU dependency.
  Hardware transcoding later needs `compose_app` to pass devices through as well.
- **Transcoding in RAM.** The server's transcode directory is a RAM-backed tmpfs, mounted at
  `/transcode` (compose long syntax `type: tmpfs`, size in bytes, mode 1777) and named by the role
  in `config/encoding.xml` as `TranscodingTempPath`, so a transcode writes memory instead of the
  guest's disk. The role also turns on `EnableThrottling` (the encoder pauses once it is 60 s ahead
  of the player) and `EnableSegmentDeletion` (segments more than 300 s behind are removed), so one
  long stream holds about six minutes of output, not the whole file: at a heavy 20 Mbps that is
  roughly 1 GiB per stream. `media_transcode_tmpfs_size` (bytes, default 8 GiB = `8589934592`; `0`
  turns it off and the server transcodes into the cache volume as before; otherwise 1 GiB to 1 TiB)
  sets the size. The file is edited in place (an element at a time, an existing server's settings kept)
  and refused, untouched, when it is not well-formed or has no closing `</EncodingOptions>`; the server reads it when the container starts; a change of the size recreates the container, so
  the two always move together. After a `restore` run `install` again so the settings follow it.
  Turning it off clears only a `TranscodingTempPath` that names `/transcode`.
  - **RAM sizing rule.** tmpfs pages are charged to the container's memory cgroup (and so to the
    module's slice and the guest's RAM): `media_mem_limit` must be at least the tmpfs size plus 256 MiB
    (`/tmp`) plus 2 GiB for the server and the encoder (validation refuses less; default `12g` for the
    default 8 GiB), and the guest needs that much memory free of everything else on it (the footprint
    is 16 GB). Pages are used only as they are written, but a tmpfs that fills fails the writer: playback
    stops with a transcode error, the host is not harmed. Size it for the concurrent transcodes you
    expect (about 1 GiB each at 20 Mbps, less at typical bitrates), not for the library.
- **Read-only root.** The container runs with `read_only: true`: the server writes only `/config`,
  `/cache`, a 256 MiB tmpfs `/tmp` (the .NET runtime's pipes and sockets) and the transcode directory.
  Checked against the pinned image with the same flags (`--read-only --cap-drop ALL`, user 61010, no
  new privileges, tmpfs `/tmp` and `/transcode`): the server starts healthy and serves `/health`, and
  `/tmp`, `/transcode`, `/config` and `/cache` are the only writable paths.
  The library is mounted at its own path, so it cannot lie under `/tmp` or `/transcode` (the tmpfs
  mounts would overlap; `compose_app` refuses it).
- **Identity.** The server id is `data/device.txt` in the data directory. A client remembers a
  server by it and by its device tokens: a new id, or a lost device row, and a Fire Cube treats
  the server as a stranger and drops its login. Set `media_expected_server_id` and `health`
  fails if the answering server is any other.

## Migration: `tools/migrate/jellyfin.py`

`python3 tools/migrate/jellyfin.py import SRC DST --map /old=/new` copies an existing config/data
directory (a restored backup, a snapshot of the old guest's volume) into a new one, stopped, and
keeps what clients need: the server id, the server name and settings, users, **devices and their
tokens**, watch state and metadata. It changes only:

- library paths, old prefix to new, in one pass (longest prefix wins, a rewritten path is never
  rewritten again; a root prefix is refused), in text columns and in blobs that are UTF-8 JSON, through
  SQL one value at a time with a path boundary, never a byte substitution (which corrupts SQLite's
  record length prefixes); a blob that holds an old path but is not JSON (a binary format) makes the
  import fail, naming it. Library definitions (`root/`, `config/*.xml`) are rewritten too, CRLF kept;
- `HardwareAccelerationType` to `none` in `config/encoding.xml` (the old host's GPU settings must
  not follow it; `--no-accel-reset` keeps them), the same intent as the role's `media_hwaccel: none`;
- `MetadataPath`, `CachePath`, `TranscodingTempPath`, `EncoderAppPath` when they name a path the
  container does not have (blanked: the server then uses its defaults), reported; every other
  absolute path left in `config/*.xml` is listed as `host_paths` (`--strict` fails on them);
- Quick Connect on.

**Nothing is deleted.** The new tree is built in `DST.partial` and renamed into place only after
it verified; an existing empty `DST` is replaced, an existing data root (`data/device.txt`) only
with `--replace`, and is then renamed to `DST.before-import`. The target must differ from and not
nest with the source, be at least three components deep, not a mount point, not around a mapped
library root, and (with `--data-root`) inside the module's data root. A failed import leaves the
previous `DST` untouched and the partial tree for inspection.

It refuses to call anything verified on a source it did not understand (no users and devices tables,
or no users without `--allow-empty`), then reads both sides: the counts of users, devices,
libraries, items and watch-state rows, the device tokens and the server id (byte-identical) must
match, and no old prefix may remain. It warns about item paths under the new library roots that do
not exist on this host, and lists the symlinks it did not carry. `counts DIR` prints the server id and
the same counts, read-only, for the freeze-time comparison. Both schema generations are read (the
single database of 10.11 and the earlier `library.db` layout); a database from an older server is
migrated by the server itself on first start, so upgrade only after the import and an export. The
fixtures here are synthetic: run it against a copy of the real old `library.db` before the
rehearsal counts as proof.

Then restore it into the data root (`config/`, owned by the container's uid) and start the role with
`media_expected_server_id` set to the source's id.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness and valid inputs |
| `health` | the library still mounted or marked; every container of the spec running and healthy; `GET /health` is `Healthy`; `GET /System/Info/Public` answers with a server id (the expected one when set); Quick Connect enabled |
| `export` | the server stopped briefly, `export/media-config.tar.gz` (config without cache, logs, transcodes) and `export/listing.jsonl` (size, sha256), the server started again whatever happened |
| `backup` | the manifest naming the data root (not the library, not the cache) |
| `restore` | checks the archive against its listing and refuses a member that leaves the directory, a link or special file, or an archive with no `data/device.txt`; extracts beside the config and checks it (no link; the expected server id when set) while the server still runs; only then stops it, moves the live config aside (`config.before-restore`) and the verified one in, and starts it. A failure leaves it stopped, saying so |
| `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump |

`health` calls `/System/Info/Public` (anonymous); `/System/Info` itself needs a signed-in user and
the role signs in as no one.

## Using it in a site

The overlay adds: the selection (`slots.media` provider `media`, an instance named anything but `media` (the module id is a core-name clash), e.g. `media-server`, placement `server`), the
guest (resources and the library mount at `media_library_path`), the registry row exactly as bound
(plus at most `standing`, `backup_job`, `scope`; its `public_hostname` is the site's), the grants
(`egress.media.server: [internet]`, `public_routes`), group variables (`media_library_path`,
`media_mem_limit` and `media_transcode_tmpfs_size` when the guest's RAM differs from the 16 GB default, `media_gid` of the mount's group, `media_published_url`, `media_expected_server_id` at a cutover)
and the firewall: the edge and the TV clients' zone to the port.
