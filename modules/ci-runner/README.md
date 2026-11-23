<!-- SPDX-License-Identifier: Apache-2.0 -->
# ci-runner: an ephemeral CI runner pool

A feature module that keeps **N CI job slots** on one host. Every job runs in a **fresh VM**
booted from a **golden image** built from a pinned base cloud image and a pinned runner agent,
with **one single-use runner registration**; the VM powers off after its one job and every file
of it (disk, seed, registration) is destroyed before the slot takes the next registration.
Nothing carries from one job to the next.

## How it works

```
trusted side (holds the forge credential)          runner host (holds no forge credential)
  hnx-ci-feeder  --ssh, key forced to "feed"-->  spool/<name>.jit
                                                   |  atomic rename (one slot per registration)
                                                 slots/<n>/  disk.qcow2 (copy-on-write over the golden image)
                                                             seed.iso   (the registration only)
                                                   |  KVM guest, user-mode networking, as hnx-<id>
                                                 job VM: one job, then power off -> slot emptied
```

* **Slots** are `hnx-<id>-slot@<n>.service` units (`Restart=always`). One run of the unit is one
  job: empty the slot directory, claim the oldest spooled registration by `rename(2)`, create the
  overlay disk and the seed, boot the VM, wait for it to power off (killed at
  `ci_runner_job_timeout_s`), keep the console's tail as `slots/<n>.last.log`, empty the directory.
* **The golden image** is built once per (base digest, agent digest, build seed): the base image is
  booted with `templates/build-user-data.j2`, which installs the toolchain the CI workflows expect
  of a hosted image (a container engine with compose and buildx, compilers, git, jq, python, zstd,
  ...), the runner agent (checked against its sha256), and a `hnx-ci-job` unit that runs the agent
  with the seed's registration and powers the VM off on success *and* failure. It then resets
  cloud-init so every job VM is a new instance. The image is kept only when the build printed its
  marker on the console; it is built beside the current one and `images/current` is re-pointed, so
  a running job is never interrupted (each slot takes the new image at its next run).
* **The feeder** (`files/hnx_ci_feeder.py`) runs where the forge credential already lives. It
  mints one just-in-time registration per idle slot (plus a small buffer), pushes it over SSH to
  the host's forced command, deletes registrations that were orphaned (offline, not busy, neither
  spooled nor held by a slot), and with `--selection-var` sets a repository variable (the workflow's switch) to `on` while the
  host answers and to `off` after `--down-after` seconds without it, so new workflow runs are not
  routed to a pool that is gone.

## Isolation

* **No state between jobs**: a fresh copy-on-write disk per job over a read-only golden image, the
  slot directory emptied before and after; docker, if a job uses it, runs inside the job VM.
* **No credential on the host**: the host holds single-use registrations only; the feeder's key
  logs in as the slots' account, and its root-owned `authorized_keys` entry is
  `restrict,command="... hnx-ci-slot feed"` (no shell, no forwarding, no terminal). Every file of
  the pool is that account's alone (0700 directories, 0600/0400 files).
* **Network**: the job VMs use user-mode networking, so their traffic leaves the host as the slots'
  account. The egress table (`templates/egress.nft.j2`) lets that account reach the resolvers on
  port 53 and public addresses on `ci_runner_egress_tcp_ports`/`ci_runner_egress_udp_ports`, and
  refuses every private, shared (CGNAT and tailnet) space, loopback (the VMs' gateway is the host's
  loopback), link-local, multicast and reserved range and all IPv6, then denies the rest. The slot
  unit refuses to start while the table is not loaded. The site adds the hypervisor's firewall for
  the guest (default-deny out, the same public-only allows) and places the guest on a zone that
  reaches no lab network.
* **Untrusted code**: a public repository's fork pull requests must never be routed here. The
  workflow side (route same-repository events only; fork events always to hosted runners) and the
  forge's fork-approval policy are the repository's settings, not this module's.

## Inputs (required, no defaults)

| Input | What |
|---|---|
| `ci_runner_logical_id` | the instance id |
| `ci_runner_base_image_url`, `ci_runner_base_image_sha256` | the base cloud image (an x86-64 image of the hosted runners' distribution) and its digest |
| `ci_runner_agent_url`, `ci_runner_agent_sha256` | the runner agent's release archive and its digest |
| `ci_runner_feed_pubkey` | the feeder's SSH public key |
| `ci_runner_resolvers` | the host's resolver addresses (the only private addresses a job VM reaches, on 53) |

Optional: `ci_runner_toolcache_pythons` (a list of `{url, sha256}` of the setup action's python-versions archives) puts those Pythons in the golden image's tool cache (`/opt/hostedtoolcache`), so a job's setup step finds one and downloads nothing.

The slot size (`ci_runner_slots`, `_slot_vcpus`, `_slot_memory_mb`, `_slot_disk_gb`) is the site's;
the readiness hook refuses a host whose memory cannot hold every slot at once.

## Placement

One `runner` host role, a VM with **nested virtualisation** (a host-passthrough CPU type on a
hypervisor whose KVM module allows nesting): readiness fails without `/dev/kvm`. Grant its
internet egress (`grants.egress.ci-runner.runner: [internet]`).

## The feeder

Run it on the trusted side, e.g. as a user service:

```sh
hnx-ci-feeder --repo <owner>/<name> --host <slots account>@<runner host> --ssh-key <key> \
  --known-hosts <file> --labels self-hosted,linux,x64,<pool label> --selection-var <SWITCH VARIABLE>
```

The token comes from `HNX_CI_FORGE_TOKEN` or, by default, the forge CLI's stored login
(`--token-command`); it needs administration of the repository's runners, never leaves the
feeder's process and is never printed. Health on the host fails when no slot holds a registration
and none is spooled (the feeder is not running).

## Lifecycle

* **upgrade**: change a pin (URL and digest together); the next converge builds the new golden
  image beside the old one. Old images are kept for the operator to delete.
* **remove**: stops the slots and the table's unit, removes units, scripts, configuration and the
  feed key; the data root (the images) is kept. No data is owned, so nothing is exported.
