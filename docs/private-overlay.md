---
summary: 'The public repo and the private overlay: what lives where, how hnx finds private data, encryption, bootstrapping a server, the runner, reviews and deploys.'
---
<!-- SPDX-License-Identifier: Apache-2.0 -->
# The public repository and the private overlay

homelab-next is public: code, schemas, fictional examples and CI. A real lab is not: its site,
guests, registry, registers, strategy and deploy live in a **private overlay**, a second repository
the operator owns. Credentials live in neither: git holds their *names*, OpenBao holds their
values, and the keys that open everything stay offline. The public contracts and the overlay
together are **Veritas**, the single source of truth
([ADR-0028](adr/0028-veritas-single-source-of-truth.md)). This page is the whole guide: the layout,
how hnx reads the private data, how a new server is bootstrapped, how a deploy runs without the
workstation, how each key is rotated, and what an attacker gets from each piece (including what
the deploy still holds as standing credentials). The decision is
[ADR-0021](adr/0021-public-and-private-repositories.md) (extending
[ADR-0011](adr/0011-public-private-split-and-licensing.md)); the skeleton to copy is
[`examples/private-overlay/`](../examples/private-overlay/README.md); the first deploy is the
runbook RB 3, [First deploy from the private repository](../examples/registers/runbooks/01a15f29-ff7e-764c-a17e-d2d50c304e9b.md)
(uid `01a15f29-ff7e-764c-a17e-d2d50c304e9b`; the number is computed, ADR-0019).

## The two repositories

```text
homelab-next/  (PUBLIC)                       lab-private/  (PRIVATE, the operator's)
├── homelabnext/  schemas/  profiles/         ├── .hnx-private-overlay.yml   marker, vault globs, sealed paths
├── ansible/roles/  ansible/plugins/          ├── .sops.yaml                 sealed paths, age recipients
├── tools/  (leak_scan, private_leak_check)   ├── .github/CODEOWNERS         owner review on .github/ etc.
├── examples/                fictional lab    ├── .github/workflows/
│   └── private-overlay/     this skeleton    │   ├── checks.yml             every PR, no secrets
│                                             │   └── deploy.yml             main only, Environment
├── docs/                                     ├── ansible.cfg                roles from ./hnx
└── .github/workflows/  (CI only; never a     ├── ansible/inventory/production/  (+ vault.yml)
    deploy, never a secret, never a           ├── ansible/known_hosts  ansible/playbooks/site.yml
    self-hosted runner)                       ├── bin/vault-pass-client.py
                                              ├── runner/job-started.sh      self-hosted runner hook
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
| Real site, registry, guests, registers, strategy, customizations, the MCP catalog (`lab/mcp/`) and its render specs, the module selection with the site's network scope (`lab/modules.yml`, [modules](modules.md#the-network-scope)) | private `lab/` | plain text under the repository's access control |
| Real data that would hurt if the private repository leaked (WAN addresses, peer details) | private `lab/sealed/` | SOPS + age, one file at a time |
| Inventory variables that must stay confidential and no role takes as a reference | private `ansible/inventory/*/group_vars/*/vault.yml` | ansible-vault |
| Credentials (passwords, tokens, API keys, enrollment secrets), and the vault password | OpenBao | referenced in git as `secret:<name>`; the deploy reads them by name through its AppRole |
| The deploy's own credentials (the AppRole `secret_id`, age identity, SSH key) | the private repository's protected Actions Environment `production` | Actions secrets (Tailscale needs none: workload identity federation) |
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
* **The MCP catalog.** The real catalog is `lab/mcp/<id>.yml`, beside `lab/services.yml`
  ([MCP catalog](mcp-catalog.md)). With `HNX_EXAMPLES_DIR=lab` the agent compiler, lint and
  keyring derive their MCP classes from it; `hnx mcp catalog check --catalog lab/mcp --registry
  lab/services.yml` checks it, `hnx docs systems ... lab/services.yml` finds it beside the
  registry, and the overlay's render specs (`lab/mcp/clients/*.yml`) write its runtimes' client
  configs. Its records hold `secret:` names only; `hnx mcp catalog import` turns an existing
  lab's client configs into draft records without copying a credential.
* **Credentials.** A registry service or a role names a credential as `secret:<name>`. On the
  Ansible controller the `hnx_secret` lookup resolves it:
  * **from OpenBao** when `BAO_ADDR` is set (the deploy): KV v2 `<BAO_KV_MOUNT>/data/<name>`
    (mount `secret`), field `BAO_FIELD` (`value`), over `https://` only, verified against
    `BAO_CACERT`, redirects refused. It logs in with the AppRole (`BAO_ROLE_ID`, `BAO_SECRET_ID`)
    once per lookup, reads, and revokes that token (`auth/token/revoke-self`) at once; a revoke
    that fails is a warning and the token lapses at the role's short TTL. `BAO_TOKEN` is used as
    given instead and left alone. In this mode nothing else is consulted, so a stray
    `HNX_SECRET_*` variable cannot shadow a value;
  * **from the environment or a directory** otherwise (lab-in-a-box, the conformance lab):
    `HNX_SECRET_<NAME>` (`homelabnext.registry.model.secret_env_name`), else
    `<hnx_secrets_dir>/<name>` (a root-only directory outside the repository). That mapping folds
    every non-alphanumeric to `_`, so `secret:a/b`, `secret:a-b` and `secret:a.b` share one
    variable: two of them in one lookup or one controller process are refused (and
    `hnx registry validate` refuses two in one registry), rather than one silently getting the
    other's value. Give secrets names that stay distinct after the mapping.
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

Both are checked in CI by `tools/private_leak_check.py private .`, and neither check trusts the
overlay's own configuration to say what must be sealed:

* **SOPS.** Every file under `lab/sealed/` (pinned in the tool, so one commit cannot drop it), under
  the marker's `sealed_paths`, or covered by a root `.sops.yaml` rule must be SOPS-encrypted
  *throughout*: real metadata (a well-formed `mac`, at least one recipient, no unknown key), every
  value and comment a well-formed `ENC[AES256_GCM,data:…,iv:…,tag:…,type:…]` token, no key set
  twice in one mapping, except keys ending in the `unencrypted_suffix`. That suffix is the SOPS
  default `_unencrypted` or the one the marker pins (`unencrypted_suffix: _plain`); a file that
  names any other one is sealed only in part. A file sealed only in part (`encrypted_regex`,
  `unencrypted_regex`, `encrypted_suffix`, the comment regexes, `mac_only_encrypted`) fails. A
  token is masked from the secret scan only in a SOPS file and only as a whole value or comment:
  its `data:` is any base64, so anywhere else it is scanned as text. A
  `.sops.yaml` that narrows the pinned paths (no rule covers `lab/sealed/`, a rule there that
  encrypts only in part, a nested `.sops.yaml` that shadows the root one, or no `.sops.yaml` while
  sealed files exist) is itself a finding. A `README.md` is the one plain file name.
* **ansible-vault.** A `vault.yml` (or a file the marker's `ansible_vault_files` globs name) must be
  the envelope and nothing else: the `ANSIBLE_VAULT` header line (format 1.1, or 1.2 with a
  vault id label, AES256), then
  hex lines only, whose payload is the salt, HMAC and ciphertext. Plain text after a valid header
  fails, and a header no longer hides the rest of any other file from the secret scan.
* **Unscanned files.** A file the check cannot read as text (binary, larger than 5 MB, unreadable)
  is a finding unless the marker's `allow_unscanned` globs name it; a sealed or vault file is
  never let through. UTF-16 without a byte-order mark is decoded and scanned.

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
   if you keep it there), for example:

   ```sh
   bao write auth/approle/role/hnx-deploy token_policies=hnx-deploy \
     token_ttl=5m token_max_ttl=15m token_type=service \
     secret_id_ttl=720h secret_id_num_uses=0 \
     token_bound_cidrs=<the deploy's source range> secret_id_bound_cidrs=<the same>
   bao read -field=role_id auth/approle/role/hnx-deploy/role-id          # variable BAO_ROLE_ID
   bao write -f -field=secret_id auth/approle/role/hnx-deploy/secret-id  # secret BAO_SECRET_ID
   ```

   Every lookup and the vault password client log in, read and revoke their own token, so a
   token lives for one read; the `secret_id` is reusable within its TTL (a use count would run out
   mid-deploy), so keep that TTL short and rotate it (below). Bound the CIDRs to the tailnet range
   the deploy node gets, or the runner VM's subnet. Generate a second age identity for the deploy
   and add its recipient to `.sops.yaml` (`sops updatekeys` on existing files).
5. **A path into the lab.** Either
   * **Tailscale** (no inbound exposure): declare the deploy's access in `lab/site.yml`
     (`tailnet.deploy`, [below](#tailscale-the-deploy-tag-least-access)), including an exception
     for the OpenBao port, render the tailnet policy and push it (its `tests` must pass), and
     create a **federated identity** (workload identity federation) with the `auth_keys` scope and
     tag `tag:ci-deploy`, issuer `https://token.actions.githubusercontent.com`, subject
     `repo:<owner>/<repo>:environment:production`: only a job of this repository running in the
     `production` Environment (which only `main` reaches) can mint a node, and no Tailscale secret
     is stored anywhere; or
   * **a self-hosted runner inside the lab**: **ephemeral, just-in-time, one job per fresh VM**,
     with the job-started hook, as [the self-hosted runner](#the-self-hosted-runner) describes. A
     persistent runner is not an option: see that section for why.
6. **The Environment.** In the private repository's settings create the Environment
   `production`: deployment branches `main` only (plus required reviewers where your plan has
   them, see [GitHub plans](#github-plans)).
   * **Secrets:** `BAO_SECRET_ID` (the AppRole's), `SOPS_AGE_KEY` (the deploy identity),
     `DEPLOY_SSH_KEY`; `ANSIBLE_VAULT_PASSWORD` only if the vault password is not in OpenBao. No
     role credential is an Actions secret (they are read from OpenBao by name) and Tailscale
     needs no secret.
   * **Variables** (Environment variables, so only the deploy job sees them): `HNX_REF` (a full
     homelab-next commit SHA), `SOPS_VERSION`, `SOPS_SHA256`, `HNX_DEPLOY_PATH` (`tailscale` or
     `self-hosted`), `BAO_ADDR` (`https://...`), `BAO_ROLE_ID`, `BAO_CACERT_PEM` (the internal
     CA's certificate, PEM), `HNX_VAULT_PASSWORD_REF` (`secret:ansible/vault-password`), and for
     Tailscale `TS_OAUTH_CLIENT_ID` and `TS_AUDIENCE` (the federated identity's client id and
     audience).
   * **Branch protection on `main`** (a ruleset or classic protection; both exist for private
     repositories on Pro): pull requests required, the `checks` job required, **one approving
     review and "Require review from Code Owners"** (the skeleton's `.github/CODEOWNERS` names
     `.github/`, `bin/`, `runner/`, `ansible.cfg`, `ansible/playbooks/`, `locks/`, `.sops.yaml` and
     the marker), and no force pushes. See [writers and reviews](#writers-and-reviews).
7. **Host keys.** Record each host's public SSH key in `ansible/known_hosts` after checking its
   fingerprint out of band (or one `@cert-authority` line for an SSH host CA).
8. **First deploy.** Merge to `main` (that runs `checks.yml` only), then start the deploy by hand:
   `gh workflow run deploy.yml --ref main` (or *Run workflow* in the Actions tab), and watch the
   run. The runbook walks through each check.

### Tailscale: the deploy tag, least access

`hnx guests render ... --target tailscale-acl` generates the tailnet policy from the site model
(one `tag:zone-<zone>` per zone, admins on SSH, the site's zone-to-zone allows) and, since site
1.2, the deploy tag from the site's own declaration
([network model](network-model.md#deploy-access-12)); nothing is added by hand:

```yaml
# lab/site.yml
tailnet:
  deploy:
    owners: [autogroup:admin]   # tagOwners of tag:ci-deploy
    zones: [mgmt, data]         # the zones the deploy configures
    exceptions:                 # the deploy reads its credentials from OpenBao
      - {zones: [mgmt], ports: [8200], reason: "OpenBao API for the deploy AppRole"}
```

renders `tag:ci-deploy` in `tagOwners`, one rule `tag:ci-deploy -> tag:zone-mgmt:22,
tag:zone-data:22` (TCP) and a `tests` block that Tailscale runs whenever the policy changes: the
tag reaches those zones on 22, is refused on other ports and on every other tag, and no zone tag
reaches it. A `*` or `any` destination is refused, and a port other than 22 needs an
`exceptions` entry with its reason. Render and push:

```sh
hnx guests render lab/guests --site lab/site.yml --target tailscale-acl --out build/tailnet
# then apply build/tailnet/tailscale-policy.hujson with Tailscale's own tooling
```

SSH (22) to the zones the deploy configures, and the OpenBao port as a declared exception,
nothing else: no subnet routes, no exit node, no access from any zone tag back to
`tag:ci-deploy`.

**Joining without a stored secret.** The pinned `tailscale/github-action` (v4.2.0) supports
**workload identity federation**: with `oauth-client-id` and `audience` (no `oauth-secret`) and
the job's `id-token` permission set to `write`, it exchanges the job's GitHub OIDC token for a
pre-authorized, **ephemeral** node tagged `tag:ci-deploy`, which disappears when the job ends.
The federated identity in the Tailscale admin console trusts issuer
`https://token.actions.githubusercontent.com` and subject
`repo:<owner>/<repo>:environment:production` only, so a workflow on another branch, a pull
request or another repository cannot mint a node, and there is no Tailscale secret in the
Environment to steal. The template uses this. If you cannot use federation, the fallback is an
OAuth client (`oauth-secret`) with only the `auth_keys` scope and only `tag:ci-deploy`, held as an
Environment secret; treat it as standing access (anyone holding it can mint `tag:ci-deploy` nodes
until it is rotated) and rotate it on a schedule.

## The self-hosted runner

**Labels do not restrict which workflow a runner accepts.** Any workflow in the repository, on any
branch or pull request, can say `runs-on: [self-hosted, hnx-deploy]`: a pull request that edits
`checks.yml` that way runs its code on the management-zone VM, without the Environment but with
the VM's network position, and on a **persistent** runner it can leave code behind (in the work
directory, the tool cache, the runner user's home or crontab) for the next deploy to run with the
Environment's secrets. So for the self-hosted path all three of these are required, not optional:

1. **Ephemeral, just-in-time runners on a fresh VM per job.** A provisioner *outside* the runner
   VM (the hypervisor host, or a small management VM) holds a fine-grained token for the one
   private repository with "Administration: read and write", and for each deploy clones a fresh VM
   from a template, hands it a JIT configuration, and destroys the VM when the job ends:

   ```sh
   # on the provisioner, per deploy (the token never reaches the runner VM)
   jit=$(gh api -X POST repos/<owner>/<repo>/actions/runners/generate-jitconfig \
     -f name="hnx-deploy-$(date -u +%Y%m%dT%H%M%S)" -F runner_group_id=1 \
     -f 'labels[]=self-hosted' -f 'labels[]=linux' -f 'labels[]=hnx-deploy' \
     -f work_folder=_work --jq .encoded_jit_config)
   # start a fresh VM from the runner template and pass it "$jit"; inside it, as the runner user:
   ./run.sh --jitconfig "$jit"     # one job, then the runner deregisters and the VM is destroyed
   ```

   A JIT runner takes exactly one job and is never re-registered; the fresh VM means nothing a
   job wrote survives it. `./config.sh --ephemeral` on a long-lived VM is not enough: the runner
   deregisters, but the VM, its disk and the runner user's files stay.
2. **The job-started hook**, [`runner/job-started.sh`](../examples/private-overlay/runner/job-started.sh)
   in the skeleton, baked into the runner template: it exits non-zero (the runner fails the job
   before its first step) unless `GITHUB_EVENT_NAME` is `workflow_dispatch`, `GITHUB_REF` is
   `refs/heads/main` and `GITHUB_WORKFLOW_REF` is exactly
   `<owner>/<repo>/.github/workflows/deploy.yml@refs/heads/main` of the repository named by
   `HNX_DEPLOY_REPOSITORY`. Install it root-owned, outside the runner's directory, and set the
   variables in the root-owned service environment (a systemd drop-in), never in the runner's
   `.env`, which the runner user can write:

   ```sh
   install -o root -g root -m 0755 runner/job-started.sh /usr/local/libexec/hnx-deploy/job-started.sh
   # /etc/systemd/system/hnx-runner.service.d/hook.conf
   [Service]
   Environment=ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/libexec/hnx-deploy/job-started.sh
   Environment=HNX_DEPLOY_REPOSITORY=<owner>/<repo>
   ```

3. **No other workflow names the runner.** `tests/overlay/` lints every workflow and fails one
   other than `deploy.yml` that names `hnx-deploy` or `self-hosted` anywhere in a job (its
   `runs-on`, a matrix, an expression). In the private repository CODEOWNERS review on
   `.github/` is what keeps a pull request from adding one; the hook is what holds when review
   does not.

The runner VM runs as an unprivileged user, is registered to the private repository only and
never to a public one, and has no route to anything but what the deploy configures.

## Writers and reviews

GitHub's write permission is broader than "may open a pull request": a writer can **dispatch**
`deploy.yml` on `main`, and the required `checks` job runs the workflow **from the pull request
itself**, so a pull request can rewrite `checks.yml` to pass. What actually gates a deploy is:

* **Branch protection on `main`** with a required approving review and **"Require review from
  Code Owners"** (the skeleton's `.github/CODEOWNERS` covers `.github/`, `bin/`, `runner/`,
  `ansible.cfg`, `ansible/playbooks/`, `locks/`, `.sops.yaml` and the marker), so nothing reaches
  `main`, and so nothing a dispatch runs, without the owner's approval. Both are available for
  private repositories on Pro.
* **The Environment's deployment-branch policy** (`main` only), so a workflow on any other ref
  gets no secret and, through federation, no tailnet node.
* **The job-started hook** on the self-hosted path.

Today the operator is the **sole writer** of the private repository. GitHub does not let an author
approve their own pull request, so with a single writer the review rule is satisfied by merging
as an administrator (the rule then binds everyone else): it protects against an added
collaborator, not against the owner's own account. Add a second writer only with the review rule
and CODEOWNERS on, and turn administrator bypass off once there is a second reviewer. Anyone with
write access can still start a deploy of what is on `main`; keep the writer list to people you
would trust to do that.

## GitHub plans

What a private repository's Environments can do depends on the account's plan. As of this
writing (verify on GitHub's "Deployments and environments" docs page before relying on it):

| Plan | Environments on a private repository | Secrets, variables, deployment-branch policy | Required reviewers, wait timer |
|---|---|---|---|
| Free | no | (repository secrets only) | no |
| Pro, Team | yes | yes | no |
| Enterprise | yes | yes | yes |

The template therefore assumes Pro or Team: the deploy runs on `workflow_dispatch` only, and the
manual dispatch from `main` is the approval step. Merges and pull requests run `checks.yml` only.

* **Starting a deploy:** `gh workflow run deploy.yml --ref main`, then `gh run watch`.
* **Creating the Environment through the API on Pro or Team:** omit `reviewers` (and
  `wait_timer`), which those plans reject for a private repository, and set the branch policy:

  ```bash
  gh api -X PUT repos/<owner>/<repo>/environments/production \
    -F 'deployment_branch_policy[protected_branches]=false' \
    -F 'deployment_branch_policy[custom_branch_policies]=true'
  gh api -X POST repos/<owner>/<repo>/environments/production/deployment-branch-policies \
    -f name=main -f type=branch
  ```

* **On Enterprise, or for a public repository** (where reviewers are available): add required
  reviewers to `production` first (`reviewers` in the same API call, or the Environment's
  settings page), then add `push: {branches: [main]}` back to `on:` in `deploy.yml`. Never add
  the push trigger without reviewers: every merge would deploy unreviewed. Keep the
  `github.ref == 'refs/heads/main'` guard either way.

## The deploy workflow, step by step

[`examples/private-overlay/.github/workflows/deploy.yml`](../examples/private-overlay/.github/workflows/deploy.yml):

1. **Trigger**: `workflow_dispatch` only, so a deploy happens when the operator starts it
   (`gh workflow run deploy.yml --ref main`); the job also checks `github.ref ==
   'refs/heads/main'`. No `push` by default, no `pull_request`, never `pull_request_target`.
2. **Permissions**: `{}` at the top; for the job `contents: read`, and `id-token` set to `write`
   for the OIDC token the Tailscale action exchanges. The token cannot write to the repository.
3. **Environment `production`**: its deployment-branch policy releases its secrets only to a run
   from `main` (and, on a plan with required reviewers, only after a reviewer approves).
4. **Pins**: refuses to start unless `HNX_REF` is a 40-hex commit SHA, the sops version and
   checksum are set, and `BAO_ADDR` is `https://` with a `BAO_ROLE_ID`. Actions are pinned to full commit SHAs (`tailscale/github-action` v4.2.0
   included).
5. **Checkouts**: the private repository, then homelab-next at `HNX_REF` into `./hnx`, both with
   `persist-credentials: false`.
6. **Tools**: pip from `hnx/constraints/bootstrap.txt` (`--require-hashes`), hnx's dependencies
   under `hnx/constraints/ci.txt`, hnx itself without dependencies, the deploy's own tools from
   `locks/deploy.txt` with hashes; sops downloaded and checked against `SOPS_SHA256`.
7. **Checks before anything is decrypted**: `python hnx/tools/private_leak_check.py private .`,
   then the OpenBao CA from `BAO_CACERT_PEM` is written to the runner's temporary directory.
8. **Validation** of the lab data, with `SOPS_AGE_KEY` set for that step only.
9. **Network**: on the Tailscale path the job joins the tailnet as `tag:ci-deploy` by workload
   identity federation (the `id-token` write permission, no stored secret); on the self-hosted path the
   ephemeral runner is already inside and its job-started hook has accepted the job.
10. **Deploy**: the SSH key goes into `ssh-agent` from the environment (never a file); the vault
    password reaches `bin/vault-pass-client.py` from OpenBao by `HNX_VAULT_PASSWORD_REF` (or as
    `HNX_VAULT_PASSWORD` from the optional secret); role credentials are read from OpenBao by the
    `hnx_secret` lookup (`BAO_ADDR`, `BAO_ROLE_ID`, `BAO_SECRET_ID`, `BAO_CACERT`), each with a
    token minted for that read and revoked after it; and `ansible-playbook
    ansible/playbooks/site.yml` runs with `host_key_checking` on and diffs off (a diff can print a
    templated secret).

Every secret is referenced only in the `env:` or `with:` of the step that needs it, never inside a
`run:` script as an expression (that is how a value ends up in a shell command line), and nothing
turns on `set -x` or step debug logging. `tests/overlay/` lints the templates by the same rules as
this repository's own workflows, and runs `actionlint` and zizmor (`zizmor --offline`; checked
with 1.31.1) over them when those tools are installed (the tests skip otherwise). CI's
`external-tools` job installs both at pinned versions with verified checksums and requires them
(`HNX_REQUIRE_TOOLS`: a missing one fails the tests there), so the templates are linted on every
push.

`checks.yml` runs on every pull request with no secret and no Environment: it only runs the
private leak check, so a pull request's code never sees a credential.

## The leak checks, both directions

| Where | Command | Fails on |
|---|---|---|
| private overlay CI | `python hnx/tools/private_leak_check.py private .` | a credential value in plain text (the `secret` patterns of `tools/leak_scan.py`, after masking well-formed ciphertext only); a sealed file (under `lab/sealed/`, the marker's `sealed_paths` or a `.sops.yaml` rule) not encrypted throughout; a `.sops.yaml` that narrows the sealed paths; a vault file that is not header plus hex; a file it could not scan and no `allow_unscanned` glob names; a committed decryption key (an age identity file, a vault password file) |
| public repository, `make check` and CI | `python tools/private_leak_check.py public .` | an overlay marker outside the fictional skeleton (or a skeleton marker that stops saying `fictional: true`); a file under `lab/` or `ansible/inventory/production/` (pinned in the tool, so neither editing nor deleting the skeleton marker switches them off) or under a further path the skeleton's `private_paths` adds; a skeleton marker whose `private_paths` drops a pinned path; a `.sops.yaml`; any SOPS-encrypted file, whatever its name or extension; a key file; a site's network scope in public git: in any file, an address-like token outside the documentation ranges under a `scope` key (at any depth; judged both on a parse of any file that is JSON, TOML or YAML and on the raw text, so Markdown prose and fences count too; an accidental commit is the threat model, deliberate obfuscation is review's), and at the few paths where a scope block may sit (the example site profiles, the generated selection examples and negatives) an entry that is not a documentation network, a block out of the selection's shape, or a file too large, too deep or malformed to parse ([modules](modules.md#the-network-scope) lists what it does not cover) |
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
* **Tailscale.** With workload identity federation there is no secret to rotate; review the
  federated identity's trusted subject (`repo:<owner>/<repo>:environment:production`) when the
  repository moves or is renamed. On the OAuth-client fallback, rotate the client secret in the
  admin console and update `TS_OAUTH_SECRET`. Ephemeral nodes need no rotation; remove stale
  `tag:ci-deploy` nodes if any remain.
* **Actions secrets.** Replace the value in the Environment; there is no history to scrub, but
  any log that ever printed a value must be deleted and the value rotated.
* **OpenBao AppRole.** Issue a new `secret_id`, update `BAO_SECRET_ID` in the Environment, destroy
  the old `secret_id` accessor (`bao write auth/approle/role/hnx-deploy/secret-id-accessor/destroy
  secret_id_accessor=<old>`). Rotate the role's policy reach down if it grew.
* **The self-hosted runner's provisioner token.** Rotate the fine-grained token that generates JIT
  configurations; it never reaches a runner VM.
* **OpenBao unseal keys.** `bao operator rekey` with a quorum of the old shares; replace the
  password-manager and paper copies; destroy the old paper.
* **The deploy SSH key.** Add the new public key to the deploy user first, swap
  `DEPLOY_SSH_KEY`, run a deploy, then remove the old public key.

## Threat model

What an attacker gets from each piece, and what still stands in the way. The honest summary: the
deploy still holds **standing** credentials (the deploy SSH key, the deploy age identity, the
AppRole `secret_id`, the vault password if kept as a secret), so anything that can read the
Environment's secrets during a deploy can keep using those until they are rotated. The table says
where that is true.

| An attacker obtains | They get | They do not get |
|---|---|---|
| the public repository | the code, schemas, fictional examples, the CI | any real address, host, credential, ciphertext or key (leak scan, reverse guard) |
| a leaked clone of the private repository | the lab's layout, addresses, inventory, procedures; secret *names* | credential values (OpenBao), sealed values (no age identity in git), vaulted values (no password in git), a deploy (needs a GitHub account with write access) |
| a collaborator account with write access | everything a clone gives, **and the deploy**: a writer can dispatch `deploy.yml` on `main`, and a pull request runs its own `checks.yml`, so a required check alone proves nothing | a change to what `main` deploys without the owner's approval, **only while** branch protection requires an approving Code Owners review ([writers and reviews](#writers-and-reviews)); today the operator is the sole writer, so this row is about the next writer |
| an Actions log | what the workflow printed: step names, check results | secrets (masked, never echoed, never expanded in a command line, no debug logging, diffs off, schema errors that never quote a value) |
| the GitHub-hosted runner during a deploy | for the job's lifetime: an ephemeral tailnet node limited to SSH on the deploy zones (and the OpenBao port); the OpenBao tokens of the reads in flight (each revoked after its read, else gone at its TTL). **Standing, until rotated:** `DEPLOY_SSH_KEY` (a static key: SSH to every deploy host from anywhere that reaches them), `SOPS_AGE_KEY` (every sealed file, including old commits), `BAO_SECRET_ID` (new tokens from the deploy's source range, within its TTL; bound it with `secret_id_bound_cidrs`), `ANSIBLE_VAULT_PASSWORD` if kept as a secret | a Tailscale credential (workload identity federation stores none; the OIDC token is valid for minutes and only for this repository's `production` Environment); the unseal keys and the operator's age identity (offline) |
| the self-hosted runner VM | the same as the hosted runner, plus a host inside the management zone while the job runs | anything that outlives the job: the runner is JIT and the VM is destroyed after one job; jobs other than the manual `deploy.yml` from `main` (the job-started hook refuses them) |
| the workstation | the operator's sessions | nothing a deploy needs: deploys run from Actions, and the offline keys are not files on it |

**What would shrink the standing set** (the target; the template is the interim):

* **SSH certificates instead of `DEPLOY_SSH_KEY`.** An OpenBao SSH secrets engine as the host CA
  for the deploy user: the deploy asks it, with its AppRole token, for a certificate valid for
  minutes (`bao write ssh/sign/hnx-deploy public_key=@<ephemeral key> ttl=15m`) for a key pair it
  generates in the job; hosts trust the CA through `TrustedUserCAKeys`. Nothing usable outlives
  the job, and the static key and its Environment secret go away. Until then, keep the deploy
  user's `authorized_keys` entry restricted (`from=` the deploy's source range) and rotate the key
  on a schedule.
* **The vault password in OpenBao** (`HNX_VAULT_PASSWORD_REF`) rather than as a secret, so it is
  read once per deploy through a revoked token instead of sitting in the Environment.
* **A short `secret_id` TTL**, bound to the deploy's source range, re-issued as part of the
  rotation routine.
## What not to do

* **Never put a key next to its ciphertext**: no age identity, vault password file or unseal key
  in either repository, not even in an ignored file next to the checkout by habit.
* **Never attach a self-hosted runner to a public repository**: any fork's pull request could run
  code on a machine inside the lab.
* **Never run a persistent self-hosted deploy runner**, and never one without the job-started
  hook: labels do not stop another workflow from landing on it, and a persistent runner keeps what
  that workflow left behind for the next deploy ([the self-hosted runner](#the-self-hosted-runner)).
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
| `HNX_SECRET_<NAME>` | the `hnx_secret` lookup (when `BAO_ADDR` is unset), registry delivery | one credential, by its `secret:<name>` |
| `BAO_ADDR`, `BAO_CACERT`, `BAO_TOKEN` or `BAO_ROLE_ID` + `BAO_SECRET_ID`, `BAO_KV_MOUNT`, `BAO_FIELD` | the `hnx_secret` lookup | when `BAO_ADDR` is set, every `secret:<name>` from OpenBao KV v2 by name, one revoked token per lookup |
| `BAO_CACERT_PEM`, `TS_OAUTH_CLIENT_ID`, `TS_AUDIENCE` | `deploy.yml` (Environment variables) | the OpenBao CA certificate; the Tailscale federated identity |
| `ACTIONS_RUNNER_HOOK_JOB_STARTED`, `HNX_DEPLOY_REPOSITORY` | the self-hosted runner service | the job-started hook and the one repository whose `deploy.yml` it accepts |
| `HNX_SOPS` | `homelabnext/sops.py` | the sops binary (default: `sops` on `PATH`) |
| `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE` | sops | the age identity that decrypts |
| `HNX_VAULT_PASSWORD` | `bin/vault-pass-client.py` | the ansible-vault password (from the Environment) |
| `HNX_VAULT_PASSWORD_REF`, `BAO_ADDR`, `BAO_CACERT`, `BAO_TOKEN` or `BAO_ROLE_ID` + `BAO_SECRET_ID`, `BAO_KV_MOUNT`, `BAO_FIELD` | `bin/vault-pass-client.py` | the password from OpenBao by name instead (no redirects followed; a token it minted is revoked after the read) |
