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
* **Memory and swap.** This release never locks its memory (2.7 reads `disable_mlock` as an
  unknown field), so the unit needs no `CAP_IPC_LOCK` and the configuration does not set it.
  Unsealed keys could therefore be paged out: the unit sets `MemorySwapMax=0` (cgroup v2), so the
  server's own memory never goes to swap whatever the host does, and main also refuses a host
  with active swap unless `openbao_allow_swap: true` (for encrypted swap).
* **Audit.** Two audit devices are declared in the configuration, so they exist from the first
  unseal and the API cannot remove them: a `file` device (`<openbao_audit_dir>/audit.log`, mode
  0600, rotated daily or past 256 MiB as the service account, with a `SIGHUP` whose failure fails
  the rotation) and a `syslog` device (facility `AUTH`, tag `openbao`: the journal, and the log
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
| `main` | `openbao_logical_id`, `openbao_api_addr`, `openbao_listen_address`, TLS | converge; start a stopped server; reload it for new TLS; never restart a running one unless allowed; refuse a pin older than the running release unless `openbao_allow_downgrade` |
| `readiness` | | fails only when the API does not answer; reports `uninitialised`, `sealed`, `unsealed-active` or `unsealed-standby`, and an owed restart |
| `health` | | fails unless initialised, unsealed and running the pinned release, and says which; a `WARN` line for an owed restart |
| `backup` | the snapshot principal | raft snapshot to `<openbao_backup_dir>/raft.snap` (0600) plus `raft.snap.json` (sha256, the release that wrote it) |
| `export` | the snapshot principal | the same, to `<openbao_export_dir>/<logical_id>.snap`: **not an open format** (below) |
| `restore` | the snapshot principal, `openbao_restore_token`, `openbao_restore_source` | refuse without the manifest `<source>.json`, on a sha256 mismatch, or when a newer release wrote it; take `pre-restore-<UTC time>.snap`; restore (`openbao_restore_force`: `snapshot-force`, for another cluster's snapshot) |
| `upgrade` | the snapshot principal, `openbao_target_version`, `openbao_target_checksums` | stage only: refuse a downgrade (against the pin and the running release); pre-upgrade snapshot; fetch and verify the target release; record it as pending |

The playbook accepts these seven hook names and nothing else (`openbao_hook`).

The hooks call the API with `ansible.builtin.uri`, verified against
`<openbao_config_dir>/tls/ca.pem`, and pass every token in an `X-Vault-Token` header inside the
module's arguments, under `no_log`: never on a command line or in an environment variable, where
`ps`, the sudo and auth logs, the journal (and the SIEM it feeds) and `-vvv` output would show it.

**The snapshot principal** is what backup, export, upgrade and the pre-restore copy use. Hand in
its AppRole, `openbao_snapshot_approle_role_id` and `openbao_snapshot_approle_secret_id` (for
instance `"{{ lookup('hnx_secret', 'secret:openbao/snapshot-secret-id') }}"`): the hook logs in,
uses the token for this run and revokes it, so no token is ever stored. A caller that minted a
token itself may pass `openbao_snapshot_token` instead. Its policy is read-only: it can save a
snapshot and cannot restore one. **The restore principal** is separate: the operator mints its
token for one restore, while present, and hands it in as `openbao_restore_token` (refused if it
equals the snapshot token). A snapshot is only as readable as the unseal keys of the cluster that
wrote it.

**Upgrading.** The `upgrade` hook stages the target release (fetched and verified beside the
running one) and takes `pre-upgrade-<running version>.snap`; it switches nothing. Take the
target's checksums from its signed `checksums.txt` (check the signature against the fingerprint
above), run the `upgrade` hook, move `openbao_version`, `openbao_checksums` and
`openbao_checksums_release` together (and the lab-in-a-box image with them), then run `main` with
`openbao_allow_restart: true` while the operator is there: the server comes back sealed on the new
release. Unseal it, then run `health`. **Rolling back is not just pointing the pin back**: the new
release may have rewritten the raft storage in a format the old one cannot read, which is why
main refuses a pin older than the running release unless `openbao_allow_downgrade: true`. Roll
back by pointing the pin back with `openbao_allow_downgrade: true`, restarting, unsealing, and
then restoring `pre-upgrade-<old version>.snap` with the old release (the `restore` hook); the old
release's directory stays for that.

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

## The operator's procedure (first start)

This is step 3 of [bootstrapping a new server](../../../docs/private-overlay.md#bootstrapping-a-new-server);
the commands below are the role-specific part. On a workstation that has the `bao` CLI and the
internal CA's certificate:

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
   pre-restore copy) and cannot restore one. Bind it to the backup host, keep its tokens short,
   and store only its `role_id` and `secret_id`, never a token (the hooks log in per run). The
   hooks run on the secret store's host, so the bound address is that host's as the server sees
   it:

   ```sh
   bao policy write hnx-snapshot - <<'EOF'
   path "sys/storage/raft/snapshot" { capabilities = ["read"] }
   EOF
   bao auth enable approle                   # if step 2 has not already
   bao write auth/approle/role/hnx-snapshot token_policies=hnx-snapshot \
     token_ttl=5m token_max_ttl=10m token_type=service \
     secret_id_ttl=720h secret_id_num_uses=0 \
     secret_id_bound_cidrs=<the backup host>/32 token_bound_cidrs=<the backup host>/32
   bao read -field=role_id auth/approle/role/hnx-snapshot/role-id           # the overlay's variables
   bao write -f -field=secret_id auth/approle/role/hnx-snapshot/secret-id   # secret:openbao/snapshot-secret-id
   ```

4. **The restore policy**, with no standing credential: a restore is rare and deliberate, done
   while the operator is present, so its token is minted then and revoked afterwards:

   ```sh
   bao policy write hnx-restore - <<'EOF'
   path "sys/storage/raft/snapshot" { capabilities = ["update"] }
   EOF
   # only to restore ANOTHER cluster's snapshot (openbao_restore_force), add to it:
   #   path "sys/storage/raft/snapshot-force" { capabilities = ["update"] }
   # at restore time, from a root token generated from the shares (revoked afterwards):
   #   bao token create -policy=hnx-restore -ttl=15m -orphan
   ```

5. **Revoke the root token**: `bao token revoke -self`. A later repair that needs root generates
   one from the shares (`bao operator generate-root`) and revokes it afterwards.

**After every restart** (a reboot, an upgrade, `openbao_allow_restart`): `bao operator unseal`,
threshold times, then the `health` hook.
