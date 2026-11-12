<!-- SPDX-License-Identifier: Apache-2.0 -->
# Role `openbao`: the secret store in server mode

The production replacement for lab-in-a-box's dev-mode `secrets` service
([architecture, "It is not a deployment"](../../../docs/architecture.md#it-is-not-a-deployment-what-replaces-each-service-in-production)):
integrated (raft) storage on a dedicated directory (a single node: no `retry_join`, no cluster to
join), TLS on the listener, two audit devices (a file and syslog), a hardened systemd unit running
as an unprivileged account, and Shamir unseal by the operator
([ADR-0042](../../../docs/adr/0042-restores-are-tested-and-the-lab-can-cold-start.md) decision 6).
It implements role interface v1 ([docs/role-interface.md](../../../docs/role-interface.md)).
The playbook is [`ansible/playbooks/openbao.yml`](../../playbooks/openbao.yml) (group `cap_secrets`).

## What the role never does

It never initialises or unseals the server, never handles an unseal share or a root token, and
never enables a secrets engine or an auth method. Those are the operator's acts, at a console
(ADR-0042 decision 6: shares are never entered through an agent, the broker or a CI path). A
restart seals the server, so the role restarts a running one only when told to
(`openbao_allow_restart: true`, while the operator can unseal); otherwise it records the restart
as owed in `<openbao_state_dir>/restart-owed` (reasons merged across runs), which the readiness
hook reports and the health hook reports as a `WARN` line. A new TLS certificate or key needs no
restart: the server reloads them on `SIGHUP` (`systemctl reload`) and stays unsealed.

## Design choices

* **Native install, not a container.** The release archive is fetched over https and refused
  unless its sha256 is the pinned one (`openbao_checksums`, per architecture), then unpacked into
  `<openbao_install_dir>/<version>/` with `openbao_bin` pointing at it. The unpack has no
  `creates:`: every run compares the archive with what is on disk and unpacks again when they
  differ (a re-pinned archive, a changed `bao`). `openbao_checksums_release` records the release
  the checksums were taken for, and validate refuses it unequal to `openbao_version`, so the
  version and its checksums move together. The checksums come from
  the release's `checksums.txt` after checking its detached signature against the project's
  release key (primary fingerprint `66D15FDD87287219C8E15478D200CD702853E6D0`), so the pin is as
  content-addressed as an image digest (RL009's intent). Why not the image: the secret store is
  the first thing a cold start needs (ADR-0042 decision 7), and a container runtime would add a
  root daemon, its socket and its own start order to the trusted base of the one host that holds
  every credential; systemd's sandbox applies to the process directly. The version is the one the
  lab-in-a-box `secrets` image runs (`tools/tests/test_pin_consistency.py` holds them equal) and
  `tools/pin_freshness.py` watches it.
* **TLS always.** `openbao_tls_cert_pem` (leaf first, then intermediates),
  `openbao_tls_private_key_pem` (from the overlay's sealed variables) and `openbao_tls_ca_pem`
  (the internal CA, written to `<openbao_config_dir>/tls/ca.pem` for the hooks and for
  `BAO_CACERT`). There is no plaintext listener and no switch for one. The listener takes TLS 1.2
  or 1.3 (`openbao_tls_min_protocol`), and under 1.2 only forward-secret AEAD suites (ECDHE with
  AES-GCM or ChaCha20-Poly1305); the lab's clients (Python's `ssl`, Go, curl with OpenSSL 3) all
  speak 1.3 and these suites, and `tls13` drops 1.2 altogether.
  `openbao_tls_selfsigned_for_tests: true` instead generates a throwaway CA and server certificate
  on the host: **test runs only**, never a server that will hold a real secret (the CA key sits on
  the same disk). It is refused without the second confirmation
  `openbao_tls_selfsigned_confirm_throwaway: true` and with any supplied PEM (the CA's too); with
  the option off, a test run's CA key is deleted.
* **A public certificate (ACME)**, `openbao_tls_source: acme` (the default, `provided`, is the
  PEMs above). For a server with a public DNS name, the role obtains a certificate from a public
  CA (Let's Encrypt by default, `openbao_acme_server`) for `openbao_acme_domains` and renews it
  **on the host**, so nothing the deploy supplies ever overwrites a renewed certificate. Details
  in [A public certificate (ACME)](#a-public-certificate-acme) below.
* **Memory and swap.** This release never locks its memory (2.7 reads `disable_mlock` as an
  unknown field), so the unit needs no `CAP_IPC_LOCK` and the configuration does not set it.
  Unsealed keys could therefore be paged out: the unit sets `MemorySwapMax=0` (cgroup v2), so the
  server's own memory never goes to swap whatever the host does, and main also refuses a host
  with active swap unless `openbao_allow_swap: true` (for encrypted swap).
* **Audit.** Two audit devices are declared in the configuration, so they exist from the first
  unseal and the API cannot remove them: a `file` device (`<openbao_audit_dir>/audit.log`, mode
  0600, rotated daily as the service account, with a `SIGHUP` whose failure fails the rotation;
  its `maxsize 256M` is checked only when logrotate runs, which is once a day on Debian
  (`logrotate.timer`), so within a day the file can grow past it) and a `syslog` device (facility `AUTH`, tag `openbao`: the journal, and the log
  pipeline from there). The server answers a request while at least one device records it, so one
  failing device does not stop the store. Put `openbao_audit_dir` on its own filesystem, or
  monitor its free space: a full disk silences the file device.
* **The unit.** `Type=notify`, the service account, no capabilities, `ProtectSystem=strict` with
  only the data and audit directories writable, `MemoryDenyWriteExecute`, `@system-service`
  system calls, no core dumps, no swap, and binding only its API and cluster ports
  (`SocketBindAllow`, `SocketBindDeny=any`).
* **Restarts and patching.** A crash restart (`Restart=on-failure`) or a reboot starts whatever
  `openbao_bin` points at, sealed: after the pin moved, that is the new release. Hosts in
  `cap_secrets` should set `unattended_upgrades_reboot_time: never` (role `unattended_upgrades`),
  so a patch run never reboots the secret store while nobody is there to unseal it.

## Hooks

| Hook | Needs | Does |
|---|---|---|
| `main` | `openbao_logical_id`, `openbao_api_addr`, `openbao_listen_address`, TLS | converge; start a stopped server; reload it for new TLS; never restart a running one unless allowed; refuse a pin older than a release this host has run (below) unless `openbao_allow_downgrade` |
| `readiness` | | fails only when the API does not answer; reports `uninitialised`, `sealed`, `unsealed-active` or `unsealed-standby`, and an owed restart |
| `health` | | fails unless initialised, unsealed and running the pinned release, and says which; a `WARN` line for an owed restart; changes nothing |
| `backup` | the snapshot principal | raft snapshot to `<openbao_backup_dir>/raft.snap` (0600) plus `raft.snap.json` (sha256, the release that wrote it) |
| `export` | the snapshot principal | the same, to `<openbao_export_dir>/<logical_id>.snap`: **not an open format** (below) |
| `restore` | the snapshot principal, `openbao_restore_token`, `openbao_restore_source` | sweep staging directories a killed run left; refuse a source or manifest that is not a regular file with one name, owned by `openbao_owner` and writable by nobody else, on a path whose every directory is too, or that is outside the backup and export directories (`openbao_restore_source_unrestricted`); stage a root-only copy, refuse it if the source changed during the copy, and check THAT (manifest present, sha256, not written by a newer release); then refuse a token whose policies are not exactly `hnx-restore` or that is not minted for this one restore (identity policies, use limit, TTL); take `pre-restore-<UTC time>.snap`; restore the staged copy (`openbao_restore_force`: `snapshot-force`, for another cluster's snapshot) |
| `upgrade` | the snapshot principal, `openbao_target_version`, `openbao_target_checksums` | stage only: refuse a downgrade (against the pin and every release this host has run); pre-upgrade snapshot; fetch and verify the target release; record it as pending |

The playbook accepts these seven hook names and nothing else (`openbao_hook`).

The hooks call the API with `ansible.builtin.uri`, verified against
`<openbao_config_dir>/tls/ca.pem` (with ACME: `openbao_acme_trust_bundle`, the host's public trust
store, and by the name in `openbao_api_addr`), and pass every token in an `X-Vault-Token` header inside the
module's arguments, under `no_log`: never on a command line or in an environment variable, where
`ps`, the sudo and auth logs, the journal (and the SIEM it feeds) and `-vvv` output would show it.

**The snapshot principal** is what backup, export, upgrade and the pre-restore copy use. Its
AppRole is `openbao_snapshot_approle_role_id` (not a secret: the overlay's variables) and the
secret_id named by `openbao_snapshot_approle_secret_id_ref` (the overlay sets
`secret:openbao/snapshot-secret-id`), which the role resolves once per run through the
`hnx_secret` lookup, under `no_log`, as every other role reads a credential: there is no variable
that takes the secret_id's value. The hook logs in, uses the token for this run and revokes it,
so no token is ever stored. A caller that minted a token itself may pass `openbao_snapshot_token`
instead. Its policy is read-only: it can save a snapshot and cannot restore one. **The restore
principal** is separate: the operator mints its token for one restore, while present, and hands it
in as `openbao_restore_token`; once every local check has passed, the hook asks the server whose
it is (`auth/token/lookup-self`) and refuses it unless its policies are exactly `hnx-restore` (and
`default`), it carries no identity policies, it has exactly one use left (it was minted with
`-use-limit=2`: the server spends a use before it answers `lookup-self`, so such a token reports 1,
and a `-use-limit=3` one, which would leave a spare restore after this one, reports 2 and is
refused) and its TTL is at most 900 seconds; it refuses it equal to the snapshot token. A refusal
message names only `hnx-restore` and `default` and counts any other policy, so a hostile server
cannot have a token (or anything else) echoed into the logs. A snapshot is only as readable as the unseal keys of the cluster that wrote
it.

**Handing in a token** (`openbao_restore_token`, `openbao_snapshot_token`): never as
`-e name=value`, which puts it in the controller's process list (`ps`) and the shell's history.
Write it to a file in memory, owner-only, pass the file, and destroy it afterwards:

```sh
umask 077
bao token create -policy=hnx-restore -ttl=15m -orphan -use-limit=2 -field=token \
  | sed 's/^/openbao_restore_token: /' > /dev/shm/hnx-restore.yml
ansible-playbook openbao.yml -e openbao_hook=restore -e openbao_restore_source=<file> \
  -e @/dev/shm/hnx-restore.yml
shred -u /dev/shm/hnx-restore.yml
```

(or `vars_prompt`, or `"{{ lookup('env', 'HNX_RESTORE_TOKEN') }}"` from a variable set by
`read -rs`; never typed onto a command line). `-use-limit=2` is what a restore spends: the
`lookup-self` check and the restore itself; the token is useless afterwards even within its TTL.
Both uses come after every local check, and a run the lookup confirmed whose restore then does
not succeed (the pre-restore snapshot failed, or the restore request itself, which may or may not
have landed) revokes the token itself (`auth/token/revoke-self`; a 403 means it is already spent).
The staged copy is removed before that, and a revoke the server does not answer (sealed,
unreachable) is reported, not fatal: revoke the token by hand once it answers, or let its TTL end.
**A refused restore needs a freshly minted token**: a run refused before the lookup leaves the
token unused but live until its TTL (the role does not revoke a token it has not confirmed is the
restore principal's: it could be anyone's), so destroy it and mint another.

**What the restore checks, and what it does not.** The source and its manifest must each be a
regular file with one name (a symbolic link is refused, so is a path through one, and so is a hard
link: another name is another way to rewrite it), owned by `openbao_owner` (root), and under
`openbao_backup_dir` or `openbao_export_dir` unless `openbao_restore_source_unrestricted: true`.
"Writable by nobody else" holds for the whole path: every directory from `/` down to the source
must be owned by `openbao_owner` or root and writable by neither its group nor others (or be
root's with the sticky bit, as `/tmp`), so nobody else can swap a name on the way either; this
matters most with `openbao_restore_source_unrestricted`, which waives the location but not the
filesystem: the source and its manifest must be on `openbao_backup_dir`'s own filesystem (the same
device), and that not a FUSE or user mount (`findmnt`: a FUSE type, or a `user`, `users` or
`user_id` option), since a mount someone else controls serves whatever bytes they like whatever the
modes say. Beyond that the role cannot vouch for the filesystem; it is the operator's. They are then copied into a fresh
root-only (0700) staging directory under `openbao_backup_dir`, and stat'ed again: a source or
manifest that is no longer the same file (device, inode, size, mtime, ctime) was changed during
the copy and is refused. The sha256, the manifest checks and the restore all read that copy, which
is removed afterwards (and a staging directory a killed run left is swept at the start of a later
restore, once it is older than any restore can still be running, `2 x openbao_snapshot_timeout +
10 x openbao_health_timeout`, so a concurrent restore's is left alone), so the bytes restored are the bytes checked even if the source changes meanwhile. The manifest's sha256 protects against **corruption, not
tampering**: the manifest is unauthenticated, and whoever can rewrite a snapshot can rewrite its
manifest too. What protects a snapshot from tampering is where it lives (root's alone) and the
barrier: a snapshot is encrypted with this cluster's keys, and a forged one does not restore
without `openbao_restore_force`.

**Downgrades.** main and upgrade refuse a pin older than any release this host has run unless
`openbao_allow_downgrade: true`, and they do not trust `sys/health` alone, which says nothing
while the server is stopped. Three witnesses: the release the server runs (`sys/health`), the
release `openbao_bin` points at (`<openbao_install_dir>/<version>/bao`: what a stopped server, a
crash restart or a reboot would start), and the release recorded in
`<openbao_state_dir>/highest-release`. main alone writes the record, with what answers after its
start or restart: it is raised when a newer release answers, and lowered only by an explicit
rollback (main with `openbao_allow_downgrade: true`, when the release that answers is the pin), so
the switch is needed for that one run and the next routine main passes without it. The health hook
writes nothing (role interface v1: health changes no state); a release started outside main is
still witnessed by the link. A record that is not one (not `{"version": "<x.y.z>"}`) fails main
and upgrade by name ("... is not a release record; remove or fix it") rather than being read as
"nothing recorded".

**Upgrading.** The `upgrade` hook stages the target release (fetched and verified beside the
running one) and takes `pre-upgrade-<running version>.snap`; it switches nothing. Take the
target's checksums from its signed `checksums.txt` (check the signature against the fingerprint
above), run the `upgrade` hook, move `openbao_version`, `openbao_checksums` and
`openbao_checksums_release` together (and the lab-in-a-box image with them), then run `main` with
`openbao_allow_restart: true` while the operator is there: the server comes back sealed on the new
release. Unseal it, then run `health`. **Rolling back is not just pointing the pin back**: the new
release may have rewritten the raft storage in a format the old one cannot read, which is why
main refuses a pin older than a release this host has run unless `openbao_allow_downgrade: true`.
A rollback needs **both**: point the pin back with `openbao_allow_downgrade: true` (and
`openbao_allow_restart: true`), unseal, and then restore `pre-upgrade-<old version>.snap` with the
old release (the `restore` hook); the old release's directory stays for that. The switch alone,
without the restore, leaves the old release on storage the new one may have rewritten. That run
lowers the release record to the old pin once the old release answers, so leave
`openbao_allow_downgrade` off again afterwards: later runs need it no more. The lowered record is
not tied to proof that the pre-upgrade snapshot was restored: the role cannot tell a rollback that
did the restore from one that skipped it, so the restore is the operator's step to confirm.

If the old release cannot start or unseal on the newer storage, start it on empty storage instead
and restore into that:

1. Stop the server (`systemctl stop openbao`) and move the data directory aside
   (`mv <openbao_data_dir> <openbao_data_dir>.newer`; keep it until the rollback is proven).
2. Run main with the old pin, `openbao_allow_downgrade: true` and `openbao_allow_restart: true`: it
   recreates an empty data directory and starts the old release, uninitialised.
3. Initialise a **throwaway** cluster (`bao operator init -key-shares=1 -key-threshold=1`, its share
   and root token in `/dev/shm` only), unseal it with that share, and from its root token create
   the two policies (`hnx-snapshot`, and `hnx-restore` with `snapshot-force`) and mint **two
   distinct** tokens: one for `openbao_snapshot_token` (the pre-restore copy of the empty cluster)
   and one `-use-limit=2` token for `openbao_restore_token`.
4. Run the `restore` hook on `pre-upgrade-<old version>.snap` with `openbao_restore_force: true`
   and the two tokens (handed in as above).
5. The server now holds the original cluster's data and is sealed with the **original** keys:
   unseal it with the original shares (threshold times), run `health`, and destroy the throwaway
   share and tokens (they belonged to the cluster the restore replaced).

**Leaving this product (export).** Role interface v1 asks `export` for an open-format exit copy
(ADR-0008 decisions 1 and 4). This role does not provide one: the export is a raft snapshot,
encrypted by the barrier and readable only by this product (or the one it forked from) with the
unseal keys of the cluster that wrote it, and a plaintext dump of every secret is deliberately not
offered. The exit path is the secrets contract: `hnx secrets plan` lists every name the lab uses;
read each by name through the contract and write it into the next store. Whether to add an
open-format dump is an open operator decision.

**Snapshot manifests.** The manifest here (`service`, `kind: raft-snapshot`, `file`, `sha256`,
`bytes`, `written_by`, `format`, `restore`) is this role's own; lab-in-a-box's kv-snapshot writes
a different one. ADR-0042 decision 2 plans moving kv-snapshot into `compose_app`; the two should
converge on one schema then.

## A public certificate (ACME)

`openbao_tls_source: acme` replaces the internal CA's PEMs with a public-trust certificate, for a
server whose name lives in a public DNS zone the lab controls (it need not RESOLVE publicly: only
the challenge's TXT record is published). What `main` does:

* **The client.** [lego](https://go-acme.github.io/lego/), pinned like the server's release:
  `openbao_lego_version` with `openbao_lego_checksums` (sha256 per architecture, from the
  release's `lego_<version>_checksums.txt`; `openbao_lego_checksums_release` must equal the
  version), fetched over https into `<openbao_install_dir>/lego/<version>/`, refused on a
  checksum mismatch or a binary that reports another version. `tools/pin_freshness.py` watches it.
* **The token.** `openbao_acme_dns_token_ref` names it (`secret:<name>`), resolved through the
  `hnx_secret` lookup under `no_log` and written only to `<openbao_config_dir>/acme/dns.env`
  (root, 0600, in a 0700 directory) as `CF_DNS_API_TOKEN=...`, the renewal unit's
  `EnvironmentFile=`. It is never an argument (lego reads it from its environment), never in a
  unit, a script or a log line; the renewal script passes it to lego alone and runs `systemctl`
  without it. A Cloudflare API token needs Zone:DNS:Edit on the zone that holds the names, and
  nothing else.
* **The challenge.** DNS-01 through the provider's API, then a **fixed wait**
  (`openbao_acme_propagation_wait`, 30s) instead of lego's propagation check. That check asks the
  zone's authoritative servers, which it finds through the host's own resolvers: behind
  split-horizon DNS those resolvers answer for the zone themselves (naming an internal server),
  and a host whose firewall blocks outbound DNS cannot reach the public ones, so the check would
  never pass. The CA checks the TXT record itself, publicly, after the wait; that check is not
  weakened. The host needs outbound https to the CA and to the provider's API only.
* **Renewal.** The unit `hnx-openbao-acme.service`, started by `hnx-openbao-acme.timer` daily
  (`openbao_acme_schedule`, `Persistent=true`, a random delay of up to 30 minutes), runs
  `/usr/local/libexec/homelabnext/openbao-acme-renew`: lego renews when fewer than
  `openbao_acme_renew_days` (30) remain or the names changed (and when the CA's renewal-info
  endpoint asks for it); the script then checks what lego stored (every name verified against
  `openbao_acme_trust_bundle`, the key matching the certificate, not expired) and, when it differs
  from what the listener reads, installs the key (0640, group `openbao_group`) and the
  certificate (0644) atomically and reloads a running server with `systemctl reload` (SIGHUP: it
  stays unsealed). **It never restarts the server**, which would seal it. The unit runs as root,
  sandboxed (`ProtectSystem=strict` with only the ACME directory, the TLS directory and its
  last-run record writable, no capability but `CAP_CHOWN`).
* **Idempotent.** `main` runs the script's `--check` first and starts the unit only when the
  installed certificate is missing, names other domains, does not verify, does not match its key
  or is due; a converged host with a valid certificate reports `changed=0`, and nothing is
  reissued. A run that started the unit fails unless the certificate is valid afterwards.
* **A failed renewal is visible**: the unit is left failed (`systemctl --failed`), its last-run
  record says so (the status hub's Schedule page), `openbao_acme_on_failure` (empty by default)
  names a unit to start on failure (`OnFailure=`, e.g. a paging template unit where the host has
  one; this repository ships none, so that is the gap), and the `health` hook fails once fewer
  than `openbao_acme_health_min_days` (14) remain, which is renewal having failed for 16 days.
* **Clients** verify against the public chain: no CA file is written (`<openbao_config_dir>/tls/ca.pem`
  from an earlier supplied-PEM run is removed), the hooks verify against
  `openbao_acme_trust_bundle` by the name in `openbao_api_addr`, and `BAO_CACERT` stays unset on
  a client whose system trust store holds the public roots (or points at that store). So the host
  of `openbao_api_addr` must be one of `openbao_acme_domains` (validate refuses otherwise) and
  must resolve, **on this host too**, to `openbao_listen_address`: an internal DNS record.

Tests and dry runs set `openbao_acme_server` to the staging directory
(`https://acme-staging-v02.api.letsencrypt.org/directory`): its certificates chain to a root no
client trusts, so point `openbao_acme_trust_bundle` at a bundle holding the staging roots for such
a run. The role's own tests run lego and systemd as fakes; the path through a real CA is proven on
a real host.

## The operator's procedure (first start)

This is step 3 of [bootstrapping a new server](../../../docs/private-overlay.md#bootstrapping-a-new-server);
the commands below are the role-specific part. On a workstation that has the `bao` CLI and the
internal CA's certificate (with ACME: leave `BAO_CACERT` unset, the system trust store verifies it):

```sh
export BAO_ADDR=https://<openbao>:8200 BAO_CACERT=ca.pem
bao status                                   # Initialized false, Sealed true (readiness: uninitialised)
bao operator init -key-shares=<N> -key-threshold=<T>
#   N shares at threshold T, as you decided (ADR-0042 decision 6, Custody). Each share and the
#   initial root token go to the password manager and to paper, never to a repository, a chat
#   or an Actions secret. Nothing of it is written to a file.
bao operator unseal                          # T times, each holder typing their own share
bao status                                   # Sealed false (health passes)
export BAO_TOKEN=<the initial root token>    # typed, for the next steps only
bao secrets enable -path=secret -version=2 kv
```

Then, in this order, with the root token still set:

1. **Seed** the lab's credentials ([Seeding the credentials](../../../docs/private-overlay.md#seeding-the-credentials):
   `hnx secrets seed ... --spec lab/secrets.yml`).
2. **The deploy's AppRole** (step 4 of the same list).
3. **The snapshot principal**, read-only: it saves snapshots (backup, export, upgrade, the
   pre-restore copy) and cannot restore one. Bind it to the secret store's own address (the hooks
   run on the secret store's host, so the address that logs in is the secret store's own address
   as the server sees it), keep its tokens short and two uses long (the save and the revoke), and
   store only its `role_id` and `secret_id`, never a token (the hooks log in per run):

   ```sh
   bao policy write hnx-snapshot - <<'EOF'
   path "sys/storage/raft/snapshot" { capabilities = ["read"] }
   EOF
   bao auth enable approle                   # if step 2 has not already
   bao write auth/approle/role/hnx-snapshot token_policies=hnx-snapshot \
     token_ttl=5m token_max_ttl=10m token_type=service token_num_uses=2 \
     secret_id_ttl=720h secret_id_num_uses=0 \
     secret_id_bound_cidrs=<the secret store's own address>/32 \
     token_bound_cidrs=<the secret store's own address>/32
   bao read -field=role_id auth/approle/role/hnx-snapshot/role-id   # openbao_snapshot_approle_role_id
   bao write -f -field=secret_id auth/approle/role/hnx-snapshot/secret-id \
     | bao kv put -mount=secret openbao/snapshot-secret-id value=-   # stdin: never on a command line
   ```

   The `secret_id` expires after `secret_id_ttl` (30 days): **backups fail on day 30 unless it is
   rotated**. It is not use-limited (`secret_id_num_uses=0`): every backup, export, upgrade and
   restore logs in once, and a count would run out on a schedule nobody chose; the TTL and the
   rotation bound it instead. Rotation is the same `secret-id` write piped into
   `bao kv put` (a new KV version), then destroying the old one
   (`bao write auth/approle/role/hnx-snapshot/secret-id-accessor/destroy secret_id_accessor=<old>`;
   `bao list auth/approle/role/hnx-snapshot/secret-id` lists the accessors). So that ADR-0045's
   rotate-by audit sees it, the overlay declares it ([private-overlay.md, step 4](../../../docs/private-overlay.md#bootstrapping-a-new-server)):
   a `lab/secrets.yml` rule (`kind: external`, `how:` the command above, a `max_age` of at most
   30 days, 21 leaving a week's margin), the name in the deploy's owner map (the spec's `also:`:
   the deploy reads it), and `read` on `secret/data/openbao/snapshot-secret-id` in the deploy's
   policy (`hnx-deploy`), since the lookup runs with the deploy's AppRole.

4. **The restore policy**, with no standing credential: a restore is rare and deliberate, done
   while the operator is present, so its token is minted then and revoked afterwards:

   ```sh
   bao policy write hnx-restore - <<'EOF'
   path "sys/storage/raft/snapshot" { capabilities = ["update"] }
   EOF
   # only to restore ANOTHER cluster's snapshot (openbao_restore_force), add to it:
   #   path "sys/storage/raft/snapshot-force" { capabilities = ["update"] }
   # at restore time, from a root token generated from the shares (revoked afterwards):
   #   bao token create -policy=hnx-restore -ttl=15m -orphan -use-limit=2
   # (two uses: the hook's lookup-self check and the restore; hand it in as a file, above)
   ```

5. **Revoke the root token**: `bao token revoke -self`. A later repair that needs root generates
   one from the shares (`bao operator generate-root`) and revokes it afterwards.

**After every restart** (a reboot, an upgrade, `openbao_allow_restart`): `bao operator unseal`,
threshold times, then the `health` hook.
