<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `technitium`: the dns provider

A provider module ([module manifest](../../docs/modules.md), draft) that fills the `dns` slot with
[Technitium DNS Server](https://technitium.com/dns/), a recursive resolver and authoritative
primary. It is a **service, not a machine**: the guest it runs on is the site's guest file, and the
site's selection places the module's one host role (`server`) on it. Nothing in this directory
names a real host, address, VM id, zone or secret value; those live only in the private overlay.

| | |
|---|---|
| Slot | `dns` (contract `conformance/protocols/dns.py`), stateful, exported as zone files |
| Adapter | `homelabnext.conform.adapters.dns_zone:make` (the zone contract over the admin API) |
| Product | Technitium DNS Server 15.4.0, `docker.io/technitium/dns-server` pinned by tag and digest |
| Host role | `server`: kind `vm`, baseline `base`, footprint 1 vCPU, 1 GB, 8 GB |
| Role | `technitium` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the admin password, read by name at deploy time) |
| Egress | `internet` (recursion from the root servers, and the block lists a site configures) |
| Public route | none |

## What the role does

`roles/technitium` renders one `compose_app` service:

- **The image** is `repository:tag@sha256:digest`. 15.4.0 is the version the lab's existing server
  runs, so the zones and settings load unchanged; the pin was published at least 14 days before it
  was set. `tools/pin_freshness.py` watches it (`role:technitium/technitium_image`).
- **The container** runs as `technitium_uid:technitium_gid` (61000, an id no account on the host
  has) with every capability dropped and `no-new-privileges`: Docker lets an unprivileged user
  bind port 53 inside the container, so nothing is added back (proved against the pinned image).
  It publishes DNS (udp and tcp, `technitium_dns_port`) and the admin API and console
  (`technitium_api_port`) on **the guest's own address** (`technitium_bind`, default the
  inventory's `ansible_host`; all interfaces is refused), so the guest's stub resolver on
  loopback keeps working and a second address can sit beside it during a parallel run.
- **The admin password** (`secret:technitium/admin-password`) reaches only the compose env_file
  (`secrets/technitium.env`, 0600) through `hnx_secret` in `no_log` tasks. The server reads
  `DNS_SERVER_ADMIN_PASSWORD` **on its first start only**; after that the account lives in
  `config/`, and rotating the secret needs the console or API too. `health` signs in with the
  stored secret, so a rotation that was not applied shows up there.
- **First-start settings** are the server name (`technitium_server_domain`, which NS and SOA
  records name), recursion (`AllowOnlyForPrivateNetworks`), optional forwarders and block list
  URLs. A restored `dns.config` brings its own, replacing these.
- **The healthcheck** is a TCP connect to the web service through `bash` (the image has no `wget`
  or `curl`).

Data lives under the module's data root on the host, `technitium_data_root`
(`/var/lib/hnx-modules/technitium`): `config/` (the zones, settings and accounts; the container's),
`log/` (the container's) and `export/` (the exit copy; root's, 0700). The compose project is
`technitium_dir` (`/opt/compose/technitium`).

## The zone tooling (`roles/technitium/files/technitium_ctl.py`)

One stdlib script, installed on the guest at `technitium_ctl_path` and usable from a workstation.
The admin password is read from an environment variable, never an argument, and sent in a POST
form, never a URL. Every check that finds nothing where something is expected (no zones, no zone
file in an archive, no answer) is an error, never a pass.

| Command | What it does |
|---|---|
| `inventory`, `verify --expect {zone: count}` | the zones and each one's record count (NS and SOA included); `verify` fails on a missing zone, a different count, or no zones at all |
| `export --out DIR` | every primary zone as a zone file, `settings.zip` (the server's settings backup, without the accounts) and `listing.jsonl` (key, size, sha256, record count); a zone that is gone is moved to `stale/`, never deleted |
| `restore-check`, `restore-apply` | read an export without writing (single-link regular files owned by root or the service user, nothing the listing does not name, sizes, sha256), then import each zone and check its record count against the listing |
| `archive-check`, `archive-apply` | read an archived config tar and list what would be restored; place **only** `zones/*.zone`, `scopes/*.scope`, `dns.config` and the allowed, blocked and blocklist configs, through a staging directory beside the config |
| `answers` | ask a server over DNS on port 53 and check the rcode and, with `--expect`, exactly the values |
| `compare` | every record of every primary zone of one server against another through their APIs (SOA serial aside), and with `--dns-old`/`--dns-new` every A, AAAA, CNAME and TXT answer asked of both over DNS |

An archive restore never takes `auth.config` (the accounts: the new admin password is the secret
store's, not the old server's), `webservice.config` (its bind address), the statistics, the cache or
the downloaded block lists; a tar with a path outside what an old config folder holds, a link, a
device, an absolute or climbing path, or no zone file at all is refused.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness, and the admin password resolves (12 characters or more) |
| `health` | every container running and healthy; the admin signs in with the stored password and the zones are the expected ones (`technitium_expected_zones`: zone to record count); **the server answers the SOA of every expected zone and every probe over DNS** (`technitium_health_probes`). With neither a zone nor a probe it fails: there would be nothing to prove an answer with. Read-only |
| `export` | `export/<zone>.zone`, `settings.zip` and `listing.jsonl`, written through the API while the server runs |
| `backup` | the export, then `compose_app`'s backup manifest (the data root, export included) |
| `restore` | checks `technitium_restore_source` (an export) without writing, then imports every listed zone, overwriting, and requires each record count to equal the export's |
| `restore_archive` | reads the archived config tar (`technitium_restore_archive`) and lists what it would restore; stops the server, places the allowlisted files, starts it again whatever happened, then requires `technitium_expected_zones` to hold exactly. A restore with no expected counts is refused. It refuses to replace zones already in `config/` unless `technitium_restore_archive_overwrite` is set |
| `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump (`compose_app` upgrade) |

## Data

| Dataset | Kind | What | Export |
|---|---|---|---|
| `zones` | `state` | every primary zone, the settings backup and the listing | zone-file, by the role's export hook |

## Using it in a site

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **A guest file** (`lab/guests/<name>.yml`): a VM, baseline `base`, resources covering the
   footprint (and the docker engine), `firewall_rules` admitting port 53 (udp and tcp) from the
   lab networks and 5380 and SSH from the operator and deploy host only, and a `backup:` policy.
   The hypervisor's per-VM firewall filters before the guest; it is the control for the published
   ports (Docker publishes through its own NAT chains, so a firewall inside the guest does not
   see them).
2. **The selection** (`lab/modules.yml`): `hosts.<name>: {guest: guest:<name>}`, and
   `slots.dns: [{provider: technitium, instance: <instance>, placement: {server: <name>}}]`.
3. **The registry row** (`lab/services.yml`): `registry/services.yml`'s `dns` row renamed to the
   instance, `host` the guest's name, `version: "15.4.0"`, plus at most the lab's own `standing`,
   `backup_job` and `scope`.
4. **The secret**, by name: `technitium/admin-password` (12 characters or more).
5. **The role's variables** (the overlay's `group_vars/mod_technitium_server.yml`):
   `technitium_logical_id: <instance>` (required), `technitium_server_domain`,
   `technitium_expected_zones` and, for the health hook, optionally `technitium_health_probes`.
6. **Apply**: `docker_engine` on the module group, then the rendered `modules.yml` twice (the
   second `changed=0`), then `checks/technitium.yml`.

## Cutover from a running DNS server (parallel run, then address swap)

The server is the whole house's resolver, so the order matters and every step has a check:

1. **Build beside the old server** on a temporary address. Apply the module; it starts empty.
2. **Seed the zones** with the `restore_archive` hook from the archived config tar of the old
   server (set `technitium_restore_archive` and `technitium_expected_zones`), or `restore` from an
   `export` of the old server. The hook fails unless every expected zone is there with exactly
   its count.
3. **Prove it equals the old server**: `technitium_ctl.py compare --old-api ... --new-api ...
   --dns-old <old>:53 --dns-new <new>:53` exits 0 only when every record and every answer is the
   same. Zones changed on the old server after the archive are re-compared and re-restored (with
   `technitium_restore_archive_overwrite`) until it does.
4. **Replicas**: a secondary that pulls zones from the old server pulls from whatever answers on
   the old address. Zone options (who may transfer, who is notified) travel inside the zone files,
   so after the swap trigger one resync on each secondary and check its serial.
5. **Swap the address**: the old server is stopped first, then the new guest takes the old address
   (the guest file's `network.ip`, applied, and `ansible_host` with it, re-running the module so
   `technitium_bind` follows). Clients and the router's DHCP DNS pointers name that address, so
   nothing else changes.
6. **Verify after the swap**: `health`, `compare` is no longer possible, so ask the SOA and a
   handful of known names from a client on each lab network.
7. **Soak** (the old server stopped, not deleted) before it is removed.

## Conformance

`conformance/target.yml` binds the `dns` suite to the Technitium adapter with
`password_env: HNX_DNS_PASSWORD`. CI runs the suite through this target against a loopback
stand-in shaped after the product's API (`tests/modules/technitium_front.py`); the same suite was
also run against the pinned image itself (10 of 10 checks). Against the lab's instance:

```sh
HNX_ENDPOINT_DNS=http://<guest>:5380 HNX_DNS_PASSWORD=<admin password> \
  hnx conform --root <homelab-next checkout> run dns \
    --target <copy of conformance/target.yml with allow_plaintext: true>
```

## Known limits

- **Plain HTTP inside the lab.** The admin API and console are not behind TLS; the password
  travels unencrypted on the guest's network. The hypervisor's per-VM firewall is the control.
- **No secondary zones.** The adapter, `export` and `compare` work on **primary** zones. A server
  that is a secondary of another keeps its zones by transfer; this module does not configure that.
- **First start only.** The admin password, server name, recursion, forwarders and block lists
  from the role's variables are read on the first start; a later change needs the console or API.
- **The container's network is Docker's default bridge**, so `egress: internet` is what the server
  is configured to do, not a network rule.
- **Removal** exports first, takes the container down and deletes `secrets/technitium.env`; the data
  root (with the export) and the rest of the compose project stay for the operator.
