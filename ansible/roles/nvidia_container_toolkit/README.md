<!-- SPDX-License-Identifier: Apache-2.0 -->
# Role `nvidia_container_toolkit`: GPUs for containers by CDI name, without touching the driver

Prepares an NVIDIA GPU guest for containers that get GPUs by CDI name (`nvidia.com/gpu=0`,
`nvidia.com/gpu=all`, which [`compose_app`](../compose_app) accepts): the container toolkit
packages, pinned and held, and a CDI spec kept current. The NVIDIA driver is **not** this role's:
it is on the guest already (often installed by hand and held, with cards that must never be
restarted warm), and the role never installs, upgrades, removes or reloads it. It implements role
interface v1 ([docs/role-interface.md](../../../docs/role-interface.md)).

```yaml
- hosts: <the GPU guests' group>
  become: true
  roles:
    - role: docker_engine
      vars:
        docker_engine_log_max_size: 10m
    - role: nvidia_container_toolkit
      vars:
        nvidia_container_toolkit_expected_gpus: 4         # the one required input
        # nvidia_container_toolkit_repository: ""         # use the guest's own CUDA repository
```

## What it does

1. **Validates the inputs** and **refuses a host that is not Debian or Ubuntu on amd64 or arm64**.
2. **Adds the vendor's apt source**, unless `nvidia_container_toolkit_repository` is `""`. The source
   is flat: `<repository>/<channel>/deb/<amd64|arm64>`, suite `/`, no components, signed by the key
   fetched from `<repository>/gpgkey`. As in `docker_engine`, the key is fetched to a staging file,
   listed in a scratch GnuPG home, and installed for apt
   (`/etc/apt/keyrings/hnx-nvidia-container-toolkit.asc`) only when every primary key in it is in
   `nvidia_container_toolkit_key_fingerprints` (default: the vendor's "NVIDIA CORPORATION (Open
   Source Projects)" key, pinned by its fingerprint in `defaults/main.yml`). A lab mirror may stand in
   for the repository root; the key is never trusted for coming from it.
3. **Reads every package's version and dpkg state** (`dpkg-query`): the held packages and the
   *protected* packages, the names matching `nvidia-*`, `libnvidia-*`, `cuda-*`,
   `xserver-xorg-video-nvidia*`, `firmware-nvidia*` and `linux-(image|headers|modules)*`, the four
   toolkit packages excluded.
4. **Masks the refresh units** (see below), before any install can start them.
5. **Installs the four packages at one exact version** only if they are not all installed at it and
   held (state `hi`). On a converged host no apt command runs at all.
6. **Keeps the CDI spec current** and checks what the runtime resolves.

## The driver is never touched: how that is enforced

| Guarantee | How |
|---|---|
| Nothing is installed, upgraded or removed beside the four packages | `apt-get install -s` runs first. The run **fails before installing anything** unless every `Inst` line is one of the four toolkit packages and there is no `Remv` or `Purg` line. The message names what apt wanted and says so. A driver, kernel or library apt would pull in is the host's to decide, never the role's. |
| A hold is never overridden | Only the toolkit packages that are held are released (`apt-mark unhold <package>`, one by one, so a version bump can move them); no other package is ever released. The install uses neither `--allow-change-held-packages` nor `--allow-downgrades`. |
| The holds always come back | `apt-mark hold` on the four packages runs in an `always:` section, so a failed simulation or install leaves them held. |
| Proof afterwards | The packages are read again, and the run fails by name unless every protected package has the same version and state as before, none appeared or vanished, and every package that was held is still held. |
| No restarts, no module loads | The role runs no restart, reload, `modprobe`, `rmmod` or `nvidia-smi`, never `nvidia-ctk runtime configure` (`docker_engine` owns `daemon.json`), and never restarts docker or containerd. A test scans the role's tasks for each of those words. |

## The CDI spec

`nvidia-ctk cdi generate` writes to `<state_dir>/cdi-staged.yaml` (outside `/etc/cdi`, so a
half-written file is never loaded). The role compares its sha256 with the live
`nvidia_container_toolkit_cdi_spec` (default `/etc/cdi/nvidia.yaml`), installs it (mode 0644) only
when it differs, and removes the staging file. An empty generated spec never replaces the live one.
`nvidia-ctk cdi list` must then name `nvidia.com/gpu=all` and at least one GPU index; with
`_expected_gpus` N above 0 the indices must be exactly 0 to N-1. A count that is short, one that is
long, an empty list and a missing `all` all fail. Devices named by UUID are not counted.

**Docker reads CDI specs from `/etc/cdi` when a container asks for a device, so nothing is
restarted** when the spec changes. (The engine needs CDI support, which current Docker Engine
releases have on by default.)

## The auto-refresh choice

The base package ships `nvidia-cdi-refresh.path` and `.service`, which its postinst enables and
starts. On a driver or kernel-module event the service runs
`nvidia-ctk system create-device-nodes --load-kernel-modules` and writes `/var/run/cdi/nvidia.yaml`.
That loads kernel modules, which is exactly what a guest with cards that must not be touched warm
cannot allow.

* `nvidia_container_toolkit_auto_refresh: false` (default): the role **masks both units before the
  install**, so the postinst's start is a no-op, and removes a leftover `/var/run/cdi/nvidia.yaml`,
  so the role's own spec in `/etc/cdi` is the one CDI resolves. The mask is read with
  `systemctl is-enabled` first and reported as a change only when the units are not already
  `masked`.
* `true`: the role leaves the units alone. If it masked them in an earlier run, unmasking is by hand
  (`systemctl unmask nvidia-cdi-refresh.path nvidia-cdi-refresh.service`).

## Using the guest's own CUDA repository

A guest that already has a CUDA apt repository can serve the same four packages at the same
versions. Set `nvidia_container_toolkit_repository: ""`: the role then adds no source and no key, and
installs `<package>=<version>-<revision>` from the host's existing apt sources, with every other
guarantee above unchanged. The exact version string must exist there, or the install fails at the
simulation (the package list is refreshed first).

## GPU guests and automatic reboot

`unattended_upgrades` never moves held packages (a hand-installed kernel or driver), but an update
that wants a reboot would still reboot the guest in its window. For cards that must never be
restarted warm, give the guest a one-guest baseline that extends the shared one, so the value is
reviewed in the set ([docs/compute-model.md](../../../docs/compute-model.md), "GPU guests"):

```yaml
baselines:
  gpu-server:
    extends: [server]
    controls:
      - {id: patching, with: {reboot_time: never}}          # Automatic-Reboot "false"
      - {id: restart-required, with: {alert_reboot: true}}  # announce a pending reboot
```

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` | `nvidia-ctk --version` answers the pinned version, and `<dev_root>/nvidiactl` exists (the driver is loaded or the card passed through). Nothing talks to a GPU. |
| `health` | The four packages are installed at `<version>-<revision>` and held (`hi`); the spec exists and `nvidia-ctk cdi list` shows `=all` and the expected GPUs; and, with `auto_refresh` false, both refresh units are `masked`. |
| `upgrade` | Refuses a target that is not a newer `x.y.z` than `nvidia_container_toolkit_version`. Then set the pin (and revision) and re-run `main`. |
| `backup`, `restore`, `export` | Nothing to do: the toolkit holds no data, and the spec is generated from the driver on each run. |

## Variables

| Variable | Default |
|---|---|
| `nvidia_container_toolkit_expected_gpus` | required (0 to 16; 0 checks no count) |
| `nvidia_container_toolkit_version` / `_package_revision` | `1.20.1` / `1` (apt version `1.20.1-1`, exact) |
| `nvidia_container_toolkit_repository` | `https://nvidia.github.io/libnvidia-container` (`""`: the host's own sources) |
| `nvidia_container_toolkit_channel` | `stable` |
| `nvidia_container_toolkit_key_fingerprints` | the vendor key above |
| `nvidia_container_toolkit_cdi_spec` | `/etc/cdi/nvidia.yaml` |
| `nvidia_container_toolkit_state_dir` | `/var/lib/homelabnext/nvidia_container_toolkit` |
| `nvidia_container_toolkit_auto_refresh` | `false` |
| `nvidia_container_toolkit_{apt_get,apt_mark,dpkg_query,ctk,systemctl}_cli` | the command names (test seams) |

## Notes

* **The pin** was at least 14 days old when it was set; `tools/pin_freshness.py` watches it against
  the upstream releases. The four packages move together.
* **A second run reports `changed=0`** on a converged host: no apt command, no unit change, the spec
  untouched when its digest matches.
* **`required` GPU count.** Role interface v1 asks `main` for at least one required input, and the
  number of cards is a fact of each guest, so it is the one input with no default.
* **Check mode** reads and simulates but installs, masks and writes nothing; the post-install
  assertions that need an installed package are skipped.
