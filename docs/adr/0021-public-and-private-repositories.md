# ADR-0021: Public and private repositories

- **Status:** proposed
- **Date:** 2026-10-21
- **Related:** ADR-0011 (extended), ADR-0002, ADR-0016 decision 7, `docs/private-overlay.md`,
  `examples/private-overlay/`, `tools/private_leak_check.py`, `homelabnext/sops.py`

## Context

ADR-0011 split what is public from what stays private but left open where the private half
lives, how hnx reads it, where credentials are kept and how a deploy reaches the lab. With a real
server coming, those answers decide whether one leaked clone, one log or one runner exposes the
lab. Until now a deploy ran from the operator's workstation, which also held the keys, so the
workstation was both a single point of failure (F-16) and the place where every secret met.

## Decision

1. **Two repositories.** The public homelab-next holds code, schemas, fictional examples and CI
   only: it never carries a deploy, a secret or a self-hosted runner. A private **overlay**
   repository holds one lab: site, registry, guests, registers, strategy, customizations and
   inventory in plain text under the repository's access control, plus its deploy workflow.
   `examples/private-overlay/` is its fictional skeleton.
2. **hnx reads the overlay through the lookups it already has**: explicit paths,
   `HNX_EXAMPLES_DIR` / `HNX_DATA_DIR` (`homelabnext/paths.py`), `HNX_CUSTOMIZATIONS_DIR`. The
   overlay never carries `schemas/` or `profiles/`: those come from the pinned public commit.
3. **Credentials are never in git, encrypted or not.** Git names them (`secret:<name>`); OpenBao
   holds the values; they reach a run as `HNX_SECRET_<NAME>` (the `hnx_secret` lookup). A file
   that must be confidential but is not a credential is encrypted per file: SOPS with age (the
   default: per-value diffs, several recipients) or ansible-vault (inventory `vault.yml`). The
   site, registry, guest and customization readers decrypt SOPS files in memory through the
   optional `sops` binary and refuse to read ciphertext as data.
4. **Keys stay offline.** OpenBao unseal keys, the initial root token and the operator's age
   identity live in a password manager and on paper, never in a repository or an Actions secret.
5. **Deploys run without the workstation**: a GitHub Actions workflow in the private repository,
   started by hand (`workflow_dispatch` is the approval step: required reviewers on a private
   repository need GitHub Enterprise) on `main` only, through an Environment whose
   deployment-branch policy admits `main` alone and which holds the vault password, the deploy's age identity, its SSH key and the Tailscale OAuth
   client. It reaches the lab either by joining the tailnet with an ephemeral key tagged
   `tag:ci-deploy` (SSH to the deploy zones only) or through a self-hosted runner inside the lab
   registered to the private repository alone. Action pins are full commit SHAs; no
   `pull_request_target`; no expression expands a secret inside a `run:` script.
6. **Both halves are checked.** `tools/private_leak_check.py private` (the overlay's CI) fails on
   a credential value in plain text, a sealed file (everything under `lab/sealed/`, pinned in the
   tool rather than read from the overlay's own `.sops.yaml`, plus what the marker or a rule adds)
   that is not SOPS-encrypted throughout, a `.sops.yaml` that narrows that set, a vault file that is
   not the bare envelope, a file it could not scan, or a committed key; `tools/private_leak_check.py public` (this repository's
   `make check` and CI) fails if any part of an overlay, any SOPS ciphertext or any key is
   committed here. `tools/leak_scan.py` also flags an age identity.

## Consequences

- A leaked private clone exposes the lab's layout but no credential, sealed value or deploy
  right; a leaked log exposes nothing secret; a runner holds secrets only while a deploy the operator dispatched runs.
- The workstation is no longer needed to deploy, and no longer holds the keys a deploy uses.
- The operator maintains an Environment, an OpenBao AppRole, a Tailscale tag and its ACL (or a
  runner host), and the rotation routine in `docs/private-overlay.md`.
- The deploy pins a homelab-next commit, so a public change reaches the lab only when the overlay
  moves `HNX_REF`, through its own reviewed pull request.
- The deploy tag's tailnet access is site data (`tailnet.deploy`, site 1.2): the Tailscale policy
  generator emits `tag:ci-deploy`, its SSH rule and policy tests, and refuses a wildcard
  destination or a port beyond SSH without a stated reason.

## Alternatives

One private repository with everything (code included): forfeits public review and reuse, the
reason for ADR-0011. Secrets encrypted in git as the main store: every clone carries them forever
and rotation cannot recall old commits. Deploying from the workstation: the fleet then depends on
the laptop (F-16). A self-hosted runner on the public repository: any fork's pull request could
run code inside the lab.
