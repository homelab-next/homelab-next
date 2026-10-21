<!-- SPDX-License-Identifier: Apache-2.0 -->
# The public repository and the private overlay

homelab-next is public: code, schemas, fictional examples and CI. A real lab is not: its site,
guests, registry, registers, strategy and deploy live in a **private overlay**, a second repository
the operator owns. Credentials live in neither: git holds their *names*, OpenBao holds their
values, and the keys that open everything stay offline. This page is the whole guide: the layout,
how hnx reads the private data, how a new server is bootstrapped, how a deploy runs without the
workstation, how each key is rotated, and what an attacker gets from each piece. The decision is
[ADR-0021](adr/0021-public-and-private-repositories.md) (extending
[ADR-0011](adr/0011-public-private-split-and-licensing.md)); the skeleton to copy is
[`examples/private-overlay/`](../examples/private-overlay/README.md); the first deploy is the
runbook *First deploy from the private repository* in `examples/registers/runbooks/`.

## The two repositories

```text
homelab-next/  (PUBLIC)                       lab-private/  (PRIVATE, the operator's)
├── homelabnext/  schemas/  profiles/         ├── .hnx-private-overlay.yml   marker + vault globs
├── ansible/roles/  ansible/plugins/          ├── .sops.yaml                 sealed paths, age recipients
├── tools/  (leak_scan, private_leak_check)   ├── .github/workflows/
├── examples/                fictional lab    │   ├── checks.yml             every PR, no secrets
│   └── private-overlay/     this skeleton    │   └── deploy.yml             main only, Environment
├── docs/                                     ├── ansible.cfg                roles from ./hnx
└── .github/workflows/  (CI only; never a     ├── ansible/inventory/production/  (+ vault.yml)
    deploy, never a secret, never a           ├── ansible/known_hosts  ansible/playbooks/site.yml
    self-hosted runner)                       ├── bin/vault-pass-client.py
                                              ├── lab/   services.yml site.yml guests/ registers/
                                              │          strategy/ customizations/ sealed/
                 ┌──────────── pinned ──────► └── locks/deploy.txt          (hash-locked)
                 │  the deploy checks out homelab-next at HNX_REF (a full commit SHA) into ./hnx
```

Nothing flows the other way: the public repository never references the private one, and the
reverse guard (below) fails its CI if any part of an overlay is committed to it.

## What lives where

| What | Where | Form |
|---|---|---|
| Code, schemas, roles, the `hnx_secret` lookup, tools | public | plain text, Apache-2.0 |
| A complete fictional lab, the overlay skeleton | public `examples/` | plain text, documentation values only |
| Real site, registry, guests, registers, strategy, customizations | private `lab/` | plain text under the repository's access control |
| Real data that would hurt if the private repository leaked (WAN addresses, peer details) | private `lab/sealed/` | SOPS + age, one file at a time |
| Inventory variables that must stay confidential and no role takes as a reference | private `ansible/inventory/*/group_vars/*/vault.yml` | ansible-vault |
| Credentials (passwords, tokens, API keys, enrollment secrets) | OpenBao | referenced in git as `secret:<name>` |
| The deploy's own credentials (vault password, age identity, SSH key, Tailscale OAuth client) | the private repository's protected Actions Environment `production` | Actions secrets |
| OpenBao unseal keys and root-token recovery, the operator's age identity | offline: a password manager, plus paper in a safe place | never in any repository or Actions secret |
| Hosts' public SSH keys | private `ansible/known_hosts` | plain text (public keys are not secrets) |

## How hnx finds the private data

hnx needs no special mode for an overlay; it uses the lookups it already has.

* **Paths.** Every command that reads lab data takes the file or directory as an argument:
  `hnx registry validate lab/services.yml`, `hnx site validate lab/site.yml`,
  `hnx guests validate lab/guests --site lab/site.yml`.
* **Default example data.** A few commands fall back to the example tree through
  [`homelabnext/paths.py`](../homelabnext/paths.py) (for instance the swap rehearsal reads
  `services.yml`). `HNX_EXAMPLES_DIR=lab` points that lookup at the overlay. `HNX_DATA_DIR` also
  works when the overlay is laid out as `<root>/examples`: a kind whose directory is missing under
  it (`schemas`, `profiles`) falls through to the pinned package, so never put a `schemas/` or
  `profiles/` directory in the overlay: it would shadow the pinned ones wholesale.
* **Customizations.** `HNX_CUSTOMIZATIONS_DIR=lab/customizations` adds the overlay's records to the
  shipped profiles ([customization.md](customization.md)).
* **Credentials.** A registry service or a role names a credential as `secret:<name>`. At run
  time it is delivered as `HNX_SECRET_<NAME>` (`homelabnext.registry.model.secret_env_name`), and
  on the Ansible controller the `hnx_secret` lookup reads that variable (or
  `<hnx_secrets_dir>/<name>` on a controller that keeps them in a root-only directory outside the
  repository). Until the secrets capability's resolver replaces the stand-in lookup, the deploy
  step maps each one from an Environment secret; the value never touches git.
* **Sealed files.** The site, registry, guest and customization readers decrypt a SOPS-encrypted
  file transparently (`homelabnext/sops.py`): a file with a top-level `sops` metadata mapping is
  passed to the `sops` binary (`$HNX_SOPS`, else `sops` on `PATH`; no shell, stdin closed, a
  30 s timeout) and the plaintext stays in memory. sops finds its key the usual way
  (`SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`). Without the binary, or when decryption fails, hnx stops
  with a message that names the file; it never reads ciphertext as data. sops is optional and not
  a Python dependency.

## Encrypting a file: ansible-vault or SOPS + age

Prefer neither: a credential belongs in OpenBao, referenced by name. Encrypt a file in git only
for data that is not a credential but must not be readable by everyone with repository access,
or for inventory variables no role accepts as a reference yet.

| | ansible-vault | SOPS + age |
|---|---|---|
| What is encrypted | the whole file (or one inline `!vault` value) | each value; keys and structure stay readable |
| Diffs and review | an opaque blob: every change rewrites the file | the changed key shows as changed; reviewable |
| Recipients | one shared password per vault id | any number of age recipients per rule (operator, deploy, a second admin); add or remove one without a shared secret |
| Who can decrypt | anyone with the password | anyone with one of the identities |
| Rotation | `ansible-vault rekey` with old and new password; every holder needs the new one | `sops updatekeys` after changing recipients; `sops rotate -i` renews the data key; a removed identity cannot open new versions |
| Read by | Ansible natively | hnx readers (`homelabnext/sops.py`), `sops` itself; Ansible through `community.sops` if wanted |
| Key material | a password (Environment secret, or OpenBao by name) | an age identity (offline for the operator; Environment secret for the deploy) |
| Fits | `group_vars/*/vault.yml` next to a plain `main.yml` | `lab/sealed/*.sops.yaml`, or a whole `lab/site.yml` if you choose |

Both are checked in CI: `tools/private_leak_check.py private .` fails on a file a `.sops.yaml`
rule covers that has no SOPS metadata, and on a `vault.yml` (or a file named by the marker's
`ansible_vault_files` globs) that does not start with the ansible-vault header.

## Bootstrapping a new server

Order matters: each step needs the one before it, and nothing secret is ever written into git.

1. **Create the private repository** from the skeleton: copy `examples/private-overlay/`, delete
   `fictional: true` from `.hnx-private-overlay.yml`, protect `main` (pull requests, the
   `checks` job required).
2. **Keys offline first.** Generate the operator's age identity on the workstation
   (`age-keygen`); store it in the password manager and print a paper copy. Put its public
   recipient in `.sops.yaml`. Choose the ansible-vault password the same way.
3. **OpenBao.** Install it in server mode (raft storage, TLS from the internal CA). Initialise it:
   the unseal key shares and the initial root token go to the password manager and to paper,
   split as you decided, never into a repository, a chat or an Actions secret. Unseal, create the
   KV v2 mount (`secret/`), write the lab's credentials under the names the registry and roles use
   (`secret:<name>` maps to `secret/data/<name>`), then revoke the root token.
4. **An identity for the deploy.** Create an AppRole for the deploy with a policy that can read
   only the paths the deploy needs (and the vault password at `secret/data/ansible/vault-password`
   if you keep it there), short token TTLs, and a `secret_id` with a bounded TTL and use count.
   Generate a second age identity for the deploy and add its recipient to `.sops.yaml`
   (`sops updatekeys` on existing files).
5. **A path into the lab.** Either
   * **Tailscale** (no inbound exposure): add `tag:ci-deploy` to the tailnet policy with the least
     access below, and create an OAuth client with the `auth_keys` scope restricted to that tag; or
   * **a self-hosted runner inside the lab**: a dedicated VM in the management zone, registered to
     the private repository only, with labels `self-hosted, linux, hnx-deploy`, running as an
     unprivileged user, ideally ephemeral (`--ephemeral`, re-registered per job).
6. **The protected Environment.** In the private repository's settings create the Environment
   `production`: required reviewers (the operator), deployment branches `main` only, and the
   secrets `ANSIBLE_VAULT_PASSWORD`, `SOPS_AGE_KEY` (the deploy identity), `DEPLOY_SSH_KEY`, and for
   Tailscale `TS_OAUTH_CLIENT_ID` / `TS_OAUTH_SECRET`; role credentials as `HNX_SECRET_<NAME>`.
   Variables: `HNX_REF` (a full homelab-next commit SHA), `SOPS_VERSION`, `SOPS_SHA256`,
   `HNX_DEPLOY_PATH` (`tailscale` or `self-hosted`).
7. **Host keys.** Record each host's public SSH key in `ansible/known_hosts` after checking its
   fingerprint out of band (or one `@cert-authority` line for an SSH host CA).
8. **First deploy.** Merge to `main`, approve the deployment in the Environment, watch the run.
   The runbook walks through each check.

### Tailscale: the deploy tag, least access

`hnx guests render ... --target tailscale-acl` generates the tailnet policy from the site model
(one `tag:zone-<zone>` per zone, admins on SSH, the site's zone-to-zone allows). The deploy tag
is not generated yet; add it beside the generated rules when you push the policy:

```json
{
  "tagOwners": {"tag:ci-deploy": ["autogroup:admin"]},
  "acls": [
    {"action": "accept", "src": ["tag:ci-deploy"], "proto": "tcp",
     "dst": ["tag:zone-mgmt:22", "tag:zone-data:22"]}
  ]
}
```

SSH (22) to the zones the deploy configures, nothing else: no subnet routes, no exit node, no
access from any zone tag back to `tag:ci-deploy`. The OAuth client mints a pre-authorized,
**ephemeral** key per run, so the node disappears when the job ends and a leaked key expires.

## The deploy workflow, step by step

[`examples/private-overlay/.github/workflows/deploy.yml`](../examples/private-overlay/.github/workflows/deploy.yml):

1. **Triggers**: `push` to `main` and `workflow_dispatch`, nothing else; the job also checks
   `github.ref == 'refs/heads/main'`. No `pull_request`, never `pull_request_target`.
2. **Permissions**: `{}` at the top, `contents: read` for the job. The token cannot write.
3. **Environment `production`**: the run waits for a reviewer; only then are the Environment's
   secrets available, and only to a run from `main`.
4. **Pins**: refuses to start unless `HNX_REF` is a 40-hex commit SHA and the sops version and
   checksum are set. Actions are pinned to full commit SHAs (`tailscale/github-action` v4.2.0
   included).
5. **Checkouts**: the private repository, then homelab-next at `HNX_REF` into `./hnx`, both with
   `persist-credentials: false`.
6. **Tools**: pip from `hnx/constraints/bootstrap.txt` (`--require-hashes`), hnx's dependencies
   under `hnx/constraints/ci.txt`, hnx itself without dependencies, the deploy's own tools from
   `locks/deploy.txt` with hashes; sops downloaded and checked against `SOPS_SHA256`.
7. **Checks before anything is decrypted**: `python hnx/tools/private_leak_check.py private .`.
8. **Validation** of the lab data, with `SOPS_AGE_KEY` set for that step only.
9. **Network**: on the Tailscale path the job joins the tailnet as `tag:ci-deploy`; on the
   self-hosted path the runner is already inside.
10. **Deploy**: the SSH key goes into `ssh-agent` from the environment (never a file), the vault
    password reaches `bin/vault-pass-client.py` through `HNX_VAULT_PASSWORD`, role credentials
    arrive as `HNX_SECRET_<NAME>`, and `ansible-playbook ansible/playbooks/site.yml` runs with
    `host_key_checking` on and diffs off (a diff can print a templated secret).

Every secret is referenced only in the `env:` or `with:` of the step that needs it, never inside a
`run:` script as an expression (that is how a value ends up in a shell command line), and nothing
turns on `set -x` or step debug logging. The template passes `actionlint` and zizmor, and
`tests/overlay/` lints it by the same rules as this repository's own workflows.

`checks.yml` runs on every pull request with no secret and no Environment: it only runs the
private leak check, so a pull request's code never sees a credential.

## The leak checks, both directions

| Where | Command | Fails on |
|---|---|---|
| private overlay CI | `python hnx/tools/private_leak_check.py private .` | a credential value in plain text (the `secret` patterns of `tools/leak_scan.py`, after masking ciphertext); a file a `.sops.yaml` rule covers without SOPS metadata; a vault file without the ansible-vault header; a committed decryption key (an age identity file, a vault password file) |
| public repository, `make check` and CI | `python tools/private_leak_check.py public .` | an overlay marker outside the fictional skeleton (or a skeleton marker that stops saying `fictional: true`); a file under the skeleton's `private_paths` (`lab/`, `ansible/inventory/production/`); a `.sops.yaml`; any SOPS-encrypted file; a key file |
| public repository | `tools/leak_scan.py` (F-18, F-05) | private addresses, names, e-mails, keys and tokens, including an age identity |

Real addresses and host names are allowed in the private check (that is what the overlay is for);
two of the public scanner's `secret` patterns flag *names* (`vault`-prefixed variable names, the
vault envelope) and are left out there, because a vaulted variable and its name are the normal
shape of a private inventory.

## Rotation

Rotate on a schedule, and at once when a holder leaves or a key may have leaked.

* **ansible-vault password.** `ansible-vault rekey --vault-id default@prompt
  --new-vault-id default@prompt ansible/inventory/*/group_vars/*/vault.yml`, commit, then update
  the Environment secret `ANSIBLE_VAULT_PASSWORD` (or the OpenBao entry) and the password manager.
  Treat everything the old password protected as exposed if the old password leaked: rotate those
  values too, rekeying alone does not unpublish old commits.
* **age identities.** Generate the new identity, add its recipient to `.sops.yaml`, run
  `sops updatekeys -y` on every sealed file, then remove the old recipient and run `sops updatekeys`
  and `sops rotate -i` (a new data key). Replace `SOPS_AGE_KEY` in the Environment (deploy key) or
  the password-manager entry (operator key). Old commits stay readable with the old identity:
  if it leaked, change the sealed values themselves.
* **Tailscale.** Rotate the OAuth client secret in the admin console, update `TS_OAUTH_SECRET`;
  ephemeral keys need no rotation (each run gets a new one). Remove stale `tag:ci-deploy` nodes if
  any remain.
* **Actions secrets.** Replace the value in the Environment; there is no history to scrub, but
  any log that ever printed a value must be deleted and the value rotated.
* **OpenBao AppRole.** Issue a new `secret_id`, update the Environment, destroy the old
  `secret_id` accessor. Rotate the role's policy reach down if it grew.
* **OpenBao unseal keys.** `bao operator rekey` with a quorum of the old shares; replace the
  password-manager and paper copies; destroy the old paper.
* **The deploy SSH key.** Add the new public key to the deploy user first, swap
  `DEPLOY_SSH_KEY`, run a deploy, then remove the old public key.

## Threat model

What an attacker gets from each piece, and what still stands in the way.

| An attacker obtains | They get | They do not get |
|---|---|---|
| the public repository | the code, schemas, fictional examples, the CI | any real address, host, credential, ciphertext or key (leak scan, reverse guard) |
| the private repository (a leaked clone, a compromised collaborator account) | the lab's layout, addresses, inventory, procedures; secret *names* | credential values (OpenBao), sealed values (no age identity in git), vaulted values (no password in git), the deploy (Environment reviewers, `main` only) |
| an Actions log | what the workflow printed: step names, check results | secrets (masked, never echoed, never expanded in a command line, no debug logging, diffs off) |
| the GitHub-hosted runner during a deploy | the Environment's secrets for that run, a tailnet node limited to SSH on the deploy zones, for the job's lifetime | standing access: the node is ephemeral and the key single-use |
| the self-hosted runner host | whatever the runner user can read while a job runs, and a host inside the management zone | the unseal keys and the operator's age identity (offline); other repositories' jobs (registered to the private repository only) |
| the workstation | the operator's sessions | nothing a deploy needs: deploys run from Actions, and the offline keys are not files on it |

## What not to do

* **Never put a key next to its ciphertext**: no age identity, vault password file or unseal key
  in either repository, not even in an ignored file next to the checkout by habit.
* **Never attach a self-hosted runner to a public repository**: any fork's pull request could run
  code on a machine inside the lab.
* **Never use `pull_request_target`** in either repository, and never run the deploy on a pull
  request: it would hand the Environment's secrets to code someone else wrote.
* **Never echo a secret**, never expand `${{ secrets.* }}` inside a `run:` script, never turn on
  `set -x` or step debug logging in the deploy, never enable Ansible diffs there.
* **Never `sops -d` into a file inside the working tree**; the skeleton's `.gitignore` catches
  `*.dec.*`, but a decrypted copy is a plaintext leak waiting for `git add -A`.
* **Never copy private data into the public repository**, even "temporarily" on a branch: the
  history is public the moment it is pushed (ADR-0011).
* **Never store unseal keys in OpenBao, an Actions secret or a repository**: they are what
  recovers OpenBao when everything else is gone.

## Variables at a glance

| Variable | Read by | Meaning |
|---|---|---|
| `HNX_EXAMPLES_DIR`, `HNX_DATA_DIR` | `homelabnext/paths.py` | where default example data (the real lab, here) is found |
| `HNX_CUSTOMIZATIONS_DIR` | `hnx custom` | the overlay's customization records |
| `HNX_SECRET_<NAME>` | the `hnx_secret` lookup, registry delivery | one credential, by its `secret:<name>` |
| `HNX_SOPS` | `homelabnext/sops.py` | the sops binary (default: `sops` on `PATH`) |
| `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE` | sops | the age identity that decrypts |
| `HNX_VAULT_PASSWORD` | `bin/vault-pass-client.py` | the ansible-vault password (from the Environment) |
| `HNX_VAULT_PASSWORD_REF`, `BAO_ADDR`, `BAO_CACERT`, `BAO_TOKEN` or `BAO_ROLE_ID` + `BAO_SECRET_ID`, `BAO_KV_MOUNT`, `BAO_FIELD` | `bin/vault-pass-client.py` | the password from OpenBao by name instead |
