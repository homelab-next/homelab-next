# media-automation

The media automation stack that ran beside the media server on the old media host, as **one module,
one compose project** in the module's cgroup slice: the library managers (TV, films, music), the
indexer manager with its challenge solver, the torrent and usenet clients, the request app, the
transcode node, and the VPN client every download client routes through.

| app | role | port (published on the guest's own address) |
|---|---|---|
| Sonarr | TV library manager | 8989 |
| Radarr | film library manager | 7878 |
| Lidarr | music library manager | 8686 |
| Prowlarr | indexer manager, feeds the three above | 9696 |
| FlareSolverr | challenge solver for Prowlarr | none (compose network only) |
| qBittorrent | torrent client | 8080 (published **on the VPN container**) |
| NZBGet | usenet client | 6789 (published **on the VPN container**) |
| Seerr (the successor of Jellyseerr) | requests; **the registry row's front door** | 5055 |
| Tdarr | transcode server and an internal node (CPU) | 8265, node port 8266 |
| gluetun | the VPN client (WireGuard) | none of its own |

Slot `media-automation` (provisional: no contract yet), role `role:media_automation`, host role
`server` (6 CPU, 12 GiB, 60 GB: Tdarr transcodes and the managers' databases are the load). Every web
interface is **internal only**: no public route. An edge route for the request app is a later change to
the registry row (`public_hostname`, with the overlay's `grants.public_routes`), deliberately not made
here. Every interface has its own login (the migration carries the old accounts).

## The VPN is the only way out for the download clients

`qbittorrent` and `nzbget` have `network_mode: service:gluetun` (compose_app now accepts exactly that
form, nothing else) and **publish no ports of their own**; their two web interfaces are published on the
VPN container. They have no network of their own, so with the tunnel down they have no route at all:
they **fail closed**, which is the kill-switch (not an advisory setting). `depends_on` makes them wait
for the tunnel's own health check. The role's `health` hook proves it on the live containers (`docker
inspect`: the network mode is `container:<the VPN container>` and there are no port bindings), and the
tests prove the render. gluetun's own firewall admits answers to `media_automation_vpn_outbound_subnets`
only (the lab subnets the web interfaces are reached from) and, if the account has one, the provider's
forwarded port (`media_automation_vpn_input_ports`, which must equal the torrent client's listen port).

The other apps (managers, indexer manager, requests, transcode) use the compose network and the
guest's normal egress; only the two download clients are behind the tunnel. The apps reach the
download clients by the compose service name `gluetun` (LL-023: never an IP: the migration refuses to
leave one).

## The library

`media_automation_library_path` (default `/srv/media`; on the guest, a virtiofs share of the host's ZFS
dataset) is mounted **writable at the same path** into the three managers, the two download clients
and Tdarr: the managers import into it and the download clients write under its `downloads/`
directory (`media_automation_downloads_subdir`, beside `movies/ shows/ music/ books/ audiobooks/
workouts/`), on **one filesystem** so an import is a hardlink and not a copy. Before the containers
start the role proves the library is really there (a mount point, or the marker file
`media_automation_library_marker`, default `.hnx-media-library`, which the operator places on the
library itself): an unmounted directory would otherwise be filled by the downloaders on the guest's own
disk and every title marked missing. The role creates the missing `downloads/` subdirectories only; it
never chowns anything that exists (see "The ownership decision").
The `health` hook makes one hardlink inside `downloads/` as the apps' user (the one cheap live test that
separates "imports fail" from "the mount is wrong": LL-140) and removes it.

## Secrets (`secret:` references: the deploy resolves them from the secret store)

| reference | what it is | how to get it |
|---|---|---|
| `secret:media-automation/vpn-wireguard-private-key` | WireGuard private key of the VPN account (44 characters, base64) | the provider's WireGuard configuration generator (`PrivateKey`, in `[Interface]`); copy from the old stack's vault value |
| `secret:media-automation/vpn-wireguard-preshared-key` | the preshared key the provider mandates (44 characters) | the same configuration (`PresharedKey`, in `[Peer]`) |
| `secret:media-automation/vpn-wireguard-addresses` | the interface address(es) assigned to the key (CIDR, comma separated) | the same configuration (`Address`) |
| `secret:media-automation/qbittorrent-password` | the torrent client web password the helper timers log in with | the value the old stack's apps hold for their download client (their download client entry), set in the client's web interface if it must change |

An unset or malformed reference stops the role **before anything is rendered**, naming the reference
(never a value). The values reach only gluetun's `secrets/gluetun.env` (0600) and the helpers'
`helpers/helper.env` (0600). Not secrets: the VPN server hostnames
(`media_automation_vpn_server_hostnames`, empty lets the client pick from the provider's pool), the
provider (`media_automation_vpn_provider`, default `airvpn`).

The **apps' own API keys, the indexers' keys, the download-client entries and the web accounts are not
module secrets**: they live in each app's database and `config.xml`, and the migration tool carries
them host to host (never through git or a command line). The helper scripts read each manager's key
from its `config.xml` at run time.

## The ownership decision (the overlay makes it once; the role does not chown the library)

The old library files are owned by uid/gid **101000** (an unprivileged-container shift) and are
world-readable. `media_automation_uid` / `media_automation_gid` default to 101000 so the apps keep
writing the files they already own, and the host's virtiofs share keeps the owner. The overlay must
decide and record, once, one of:

1. **Keep 101000** (the default): leave the dataset's ownership as it is. The media server (a different
   module, uid 61010 by default) reads the library through the files' world-readable mode; nothing to do.
2. **Re-own the dataset** to a lab uid, one `chown -R` on the host dataset at cutover (operator, not the
   role), then set `media_automation_uid`/`_gid` to match.

Either way the new `config/<app>` directories are created for the configured ids, and the request app runs
as its image's own `1000:1000` (`media_automation_seerr_uid`/`_gid`), the one exception.

## Fail-closed, and what a restart of the VPN client does

A restart or recreate of gluetun keeps its container id but builds a **new network namespace**; the two
download clients keep the old one, which has no interface and no route. That is fail-closed (no traffic
can leak), but they stay dead, and their own health checks (inside the stale namespace) stay green. The
`health` hook therefore compares each client's network namespace with the VPN client's current one
(`readlink /proc/self/ns/net` in each) and fails naming the stale client; the web-interface probe catches
it too. Recovery is the `recover` hook (`tasks_from: recover`): it recreates only the clients that are out
of step (`up -d --force-recreate --no-deps`); they start again only behind gluetun's health check
(`depends_on` service_healthy), so the kill-switch holds throughout. Run it after any restart of the VPN
client (the status hub's `health` probe is the trigger; a timer for it is not shipped). The containers
restart with `unless-stopped`: a crash restarts the VPN client first, the clients follow only by recovery.
The module does not touch gluetun's DNS or IPv6 defaults (no sysctl, no `DOT` setting).

## Helper scripts: systemd timers on the guest (not StackStorm)

The old stack's three helper scripts are carried as module files (`roles/media_automation/files/`) and
run by systemd timers on the guest, as the apps' user, fully hardened (an empty
`CapabilityBoundingSet`, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateDevices`,
`PrivateTmp`, kernel and cgroup protections, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
`RestrictNamespaces`, `LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`,
`UMask=0077`). Write access is per unit: the cleanup may write **only `downloads/` and its state** (the
library is read-only for it), the rename helper the library, the stalled-torrent repair only its state.
The cleanup also refuses to run when its completed root is a symlink or lies outside `downloads/`, never
follows a link while walking, and removes only plain files whose real parent is inside `downloads/` (the
apps' uid can plant a link there, so the unit's mount confinement and the script's checks are both
required). The seccomp filter and `MemoryDenyWriteExecute` could not be exercised without systemd in CI:
the first deploy confirms the three units run (`systemctl start` each once).

| unit | what | when |
|---|---|---|
| `cleanup-downloads` | removes completed downloads that are already hardlinked into the library and no longer loaded in the torrent client (and the filename blacklist, orphaned partfiles, empty directories); fails closed when the client cannot be asked | daily 04:30 |
| `stalled-repair` | removes and re-searches a torrent with no progress for `media_automation_helper_stall_hours` (24) | hourly |
| `rename-cleanup` | renames release-style file names to the managers' own naming, then rescans | daily 05:30 |

Why timers and not StackStorm actions: two of the three work on the library's inodes and file names
(a hardlink index, `os.rename`), which only a host that has the library mounted can do, and the third needs
the torrent client's address that only the guest's network reaches; all three are idempotent and a rule that
runs them from StackStorm would only add a hop (and the new StackStorm's rules ship disabled). They can
move later as actions without changing the scripts. Each helper has a switch
(`media_automation_helper_*_enabled`). The scripts read the managers' keys from `config.xml`; the torrent
client login comes from `helpers/helper.env`. The stalled-torrent repair reports to the journal only: there is no notification endpoint and no `.150`
path. The scripts are root-owned code in `/usr/local/libexec/homelabnext/` (`hnx-media-cleanup-downloads`,
`hnx-media-stalled-repair`, `hnx-media-rename-cleanup`) that the apps' user cannot change. (The rename script can also nudge the media server's library scan when
`MEDIA_SERVER_URL` and `MEDIA_SERVER_ACCESS_KEY` are put in `helpers/helper.env` by hand; the role does not
wire it, as the key is the media server's.)

## Lessons encoded

* **LL-023** the download clients are addressed by the compose service name `gluetun`, never an IP; the migration
  reports (and with `--strict` refuses) any host written as an address.
* **LL-009** the apps' SQLite databases are changed through SQL (one column at a time), never byte
  substitution; the torrent client's resume files through a real bencode reader and writer.
* **LL-140** the health hook makes the cheap live hardlink test and reads the clients' network mode before
  anyone builds a theory from error volume.
* **LL-200** removing a poisoned queue item: `skipRedownload=true` with `blocklist=true` (the stalled-repair
  script's removal does exactly that); a known-fake release re-grabbed by an immediate re-search is a loop.
* **LL-445** the compose project is recreated by a converge; `docker compose up` does not pull
  (images are pinned by digest, nothing floats), so a repeated converge changes nothing.
* **LL-515** indexers the managers' test query can never validate retry in Prowlarr's six-hourly sync and
  show up as a climbing validation-error count: remove them from Prowlarr rather than excluding the noise.
* The request app keeps **its own** root-folder settings (`settings.json`: `activeDirectory`), separate from the
  managers'; the migration maps both.
* The filename blacklist (`qbittorrent-excluded-file-names.txt`, executables, scripts, archives, office
  documents, samples) is carried **without** its audio, image, cue, log, ebook and comic entries
  (`*.flac`, `*.mp3`, `*.jpg`, `*.pdf`, `*.cbz`, ...): this stack runs a music manager and keeps books, and
  the cleanup would have deleted those downloads on sight. The cleanup script also never deletes a file
  with such a suffix whatever list it is given (tested). `*.torrent` stays out: the client needs its own
  metadata files. **The migrated `qBittorrent.conf` still carries the old `Session\ExcludedFileNames`
  setting** (the client refuses those names at download time): review it in the client's settings after the
  import if music or book torrents are wanted.

## Migration: `tools/migrate/media_automation.py`

Reads the old volumes (`<prefix><app>_config/_data`) or this module's own `config/` layout, builds
`config/` **beside** the target (`<target>.partial`) and renames it into place only after it verified;
an existing target is moved aside (`.before-import`), never deleted. The destructive guards are in the
tool's header and tested: it refuses `/`, shallow paths, a target equal to or nested with the source, a
target outside `--data-root`, a target that is or lies in or around the library root, a symlinked or
mounted target, an unrelated non-empty target, a leftover `.partial`; it follows no symlink of the source.

* Paths are rewritten old to new **in one pass, longest prefix first** (`--map /media=/srv/media`: the old
  containers saw the library at `/media`), in every database column (SQL, parameterised), in the settings
  files, and (bencode) in the torrent client's resume files.
* Hosts are rewritten by whole token (`--strip-host-prefix media-core-` turns every old container name into
  the service name; `--host-map media-core-jellyfin=<the new media server host>` for the one that is not
  part of this stack; a stale container IP such as the one Prowlarr's download clients carry is fixed with
  `--host-map <ip>=gluetun`, reported otherwise).
* Verification re-reads the new tree: per-app counts (series, episode files, films, film files, artists,
  albums, track files, indexers, download clients, applications, root folders, requests, resume files)
  must equal the source; the managers' `config.xml` (the API key) must be byte-identical (compared by hash,
  never printed); an unrecognised schema, a missing manager and an empty primary table are errors, as is
  an import whose counts are all zero. `--owner UID:GID` and `--seerr-owner` set ownership (run as root);
  `--skip-covers` leaves the cover art for the apps to download.
* Stop the old stack (or point at a snapshot) before the final copy; run the import against the new
  target with the new stack **stopped**, then start it and run `health`.

    python3 tools/migrate/media_automation.py counts /srv/archive/.../volumes --prefix media-core_
    python3 tools/migrate/media_automation.py import /srv/archive/.../volumes /var/lib/hnx-modules/media-automation/config \
      --prefix media-core_ --map /media=/srv/media --strip-host-prefix media-core- \
      --host-map media-core-jellyfin=<media server host> --host-map <old container ip>=gluetun \
      --owner 101000:101000 --seerr-owner 1000:1000 --data-root /var/lib/hnx-modules/media-automation

## What the overlay must supply (checklist)

* `lab/modules.yml`: the slot `media-automation`, provider `media-automation`, an instance name that is not
  the module's id (the row is renamed to it), placement `server` on the media guest;
  `grants.egress.media-automation.server: [internet]`; **no** `public_routes` (internal only).
* The registry row bound as the module declares it (host = the guest, `version` = `product.version`), plus
  the lab's own standing/backup/scope.
* Guest: >= 6 CPU, 12 GiB, 60 GB, the `base` baseline, **docker_engine**, the library as a **virtiofs share
  of the host dataset mounted at `media_automation_library_path`** (and its marker file), `/dev/net/tun`.
* Group variables: `media_automation_logical_id`, **`media_automation_vpn_outbound_subnets`** (required: private, shared, link-local or loopback CIDRs only; the
  lab subnets the interfaces are reached from, as CIDRs), `media_automation_vpn_input_ports` (the provider's
  forwarded port, if any), `media_automation_vpn_server_hostnames` (optional), `media_automation_timezone`,
  `media_automation_uid`/`_gid` (the ownership decision above), `media_automation_library_path` if not
  `/srv/media`.
* Secrets seeded in the store: the four above.
* Firewall: the guest admits the lab clients (and the operator) to 8989, 7878, 8686, 9696, 8080, 6789, 5055,
  8265; nothing inbound from outside the lab. **Egress** from the guest: the VPN endpoint (UDP, the provider's
  server pool; the port is the provider's WireGuard port), the indexers, usenet providers and the managers'
  metadata hosts (the module declares `internet`; the overlay's grant and the firewall implement it).
* Run the migration, then `install.yml`, then `health`.

## Operator-owned

The VPN account details and a **live download test** (a small torrent and a small usenet item through the
tunnel, then a hardlinked import into the library) cannot be done by the module or its tests; the first
deploy also verifies that the images that have no user setting (Tdarr) and the images run with a user
override (the managers, the download clients, with their config directories owned by it) start as expected
on the guest.

## Hooks and upgrade

`readiness` (engine, inputs, library mounted, the four secrets resolve, `/dev/net/tun`), `health`,
`backup` (the data root only), `export` (every app's config, with the stack stopped, restarted whatever
happened), `restore` (hash-checked archive, no link, staged then swapped, the previous config kept as
`config.before-restore`), `upgrade` (one app's pin: `-e media_automation_upgrade_app=<app> -e
media_automation_target_image=<repo:tag@sha256:...>`; the config is exported first, since the managers
migrate their databases on first start and cannot go back). `remove` exports first and leaves the data
root, the helper units and the library.

`roles/media_automation/meta/argument_specs.yml` repeats the variable table once per hook entry point
(main, health, readiness, backup, export, restore, recover, upgrade), as the ansible argument validator
requires; the variable list is the role's `defaults/main.yml`.
