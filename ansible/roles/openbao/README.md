<!-- SPDX-License-Identifier: Apache-2.0 -->
# Role `openbao`: the secret store in server mode

The production replacement for lab-in-a-box's dev-mode `secrets` service
([architecture, "It is not a deployment"](../../../docs/architecture.md#it-is-not-a-deployment-what-replaces-each-service-in-production)):
integrated (raft) storage on a dedicated directory, TLS on the listener, a file audit device, a
hardened systemd unit running as an unprivileged account, and Shamir unseal by the operator
([ADR-0042](../../../docs/adr/0042-restores-are-tested-and-the-lab-can-cold-start.md) decision 6).
It implements role interface v1 ([docs/role-interface.md](../../../docs/role-interface.md)).
The playbook is [`ansible/playbooks/openbao.yml`](../../playbooks/openbao.yml) (group `cap_secrets`).

## What the role never does

It never initialises or unseals the server, never handles an unseal share or a root token, and
never enables a secrets engine or an auth method. Those are the operator's acts, at a console
(ADR-0042 decision 6: shares are never entered through an agent, the broker or a CI path). A
restart seals the server, so the role restarts a running one only when told to
(`openbao_allow_restart: true`, while the operator can unseal); otherwise it records the restart
as owed in `<openbao_state_dir>/restart-owed`, which the readiness hook reports.

## Design choices

* **Native install, not a container.** The release archive is fetched over https and refused
  unless its sha256 is the pinned one (`openbao_checksums`, per architecture), then unpacked into
  `<openbao_install_dir>/<version>/` with `openbao_bin` pointing at it. The checksums come from
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
  `BAO_CACERT`). There is no plaintext listener and no switch for one.
  `openbao_tls_selfsigned_for_tests: true` instead generates a throwaway CA and server certificate
  on the host: **test runs only**, never a server that will hold a real secret (the CA key sits on
  the same disk).
* **Memory and swap.** This release never locks its memory (2.7 reads `disable_mlock` as an
  unknown field), so the unit needs no `CAP_IPC_LOCK` and the configuration does not set it.
  Unsealed keys could therefore be paged out: main refuses a host with active swap unless
  `openbao_allow_swap: true` (for encrypted swap).
* **Audit.** A `file` audit device is declared in the configuration
  (`<openbao_audit_dir>/audit.log`, mode 0600, rotated daily with a `SIGHUP`), so it exists from
  the first unseal and the API cannot remove it.
* **The unit.** `Type=notify`, the service account, no capabilities, `ProtectSystem=strict` with
  only the data and audit directories writable, `MemoryDenyWriteExecute`, `@system-service`
  system calls, no core dumps (`systemd-analyze security` rates it 1.2 "OK").

## Hooks

| Hook | Needs | Does |
|---|---|---|
| `main` | `openbao_logical_id`, `openbao_api_addr`, `openbao_listen_address`, TLS | converge; start a stopped server; never restart a running one unless allowed |
| `readiness` | | fails only when the API does not answer; reports `uninitialised`, `sealed`, `unsealed-active` or `unsealed-standby`, and an owed restart |
| `health` | | fails unless initialised, unsealed and running the pinned release; says which |
| `backup` | `openbao_snapshot_token` | raft snapshot to `<openbao_backup_dir>/raft.snap` plus `raft.snap.json` (sha256, the release that wrote it) |
| `export` | `openbao_snapshot_token` | the same, to `<openbao_export_dir>/<logical_id>.snap` |
| `restore` | `openbao_snapshot_token`, `openbao_restore_source` | `bao operator raft snapshot restore` (`openbao_restore_force` for another cluster's snapshot) |
| `upgrade` | `openbao_snapshot_token`, `openbao_target_version`, `openbao_target_checksums` | refuse a downgrade; pre-upgrade snapshot; stage and verify the target release; record it as pending |

The hooks call the API at `openbao_api_addr` verified against `<openbao_config_dir>/tls/ca.pem`.
`openbao_snapshot_token` is a short-lived token of the snapshot principal (below), handed in by
the caller, for instance from the `hnx_secret` lookup
(`openbao_snapshot_token: "{{ lookup('hnx_secret', 'secret:openbao/snapshot-token') }}"`) or minted
for the run; every task that uses it carries `no_log`. A snapshot is only as readable as the
unseal keys of the cluster that wrote it.

**Upgrading.** Take the target's checksums from its signed `checksums.txt` (check the signature
against the fingerprint above), run the `upgrade` hook, move `openbao_version` and
`openbao_checksums` (and the lab-in-a-box image with them), then run `main` with
`openbao_allow_restart: true` while the operator is there: the server comes back sealed on the new
release. Unseal it, then run `health`. The previous release's directory stays for a rollback.

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

Then seed the lab's credentials ([Seeding the credentials](../../../docs/private-overlay.md#seeding-the-credentials):
`hnx secrets seed ... --spec lab/secrets.yml`), create the deploy's AppRole (step 4 of the same
list) and the snapshot principal:

```sh
bao policy write hnx-snapshot - <<'EOF'
path "sys/storage/raft/snapshot"       { capabilities = ["read", "update"] }
path "sys/storage/raft/snapshot-force" { capabilities = ["update"] }
EOF
bao auth enable approle                      # if step 4 has not already
bao write auth/approle/role/hnx-snapshot token_policies=hnx-snapshot \
  token_ttl=5m token_max_ttl=10m token_type=service secret_id_ttl=720h secret_id_num_uses=0
```

and revoke the root token: `bao token revoke -self`. A later repair that needs root generates one
from the shares (`bao operator generate-root`) and revokes it afterwards.

**After every restart** (a reboot, an upgrade, `openbao_allow_restart`): `bao operator unseal`,
threshold times, then the `health` hook.
