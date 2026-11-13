<!-- SPDX-License-Identifier: Apache-2.0 -->
# Role `docker_engine`: the container engine for `compose_app`

Docker Engine from the vendor's signed apt repository, for a guest that runs
[`compose_app`](../compose_app) applications (a `compose_app` module's host applies it first). No
baseline control binds it. It implements role interface v1
([docs/role-interface.md](../../../docs/role-interface.md)).

```yaml
- hosts: <the module's placement group>
  become: true
  roles:
    - role: docker_engine
      vars:
        docker_engine_log_max_size: 10m   # the one required input
```

## What it does

1. **Validates the inputs** (`tasks/validate.yml`): each pin is a plain `x.y.z`, the repository is
   https, every key fingerprint is 40 upper-case hex digits, and the log bounds are a size like
   `10m` and a file count of 1 to 100. These values become apt package versions, an apt source and
   daemon settings, so nothing else gets through.
2. **Refuses a host that is not Debian or Ubuntu** (`tasks/platform.yml`). The vendor publishes
   `<repository>/debian` and `<repository>/ubuntu`, with a suite per release codename.
3. **Fails closed on the signing key** (`tasks/signing_key.yml`). It fetches
   `<repository>/<debian|ubuntu>/gpg` to a staging file and lists it with `gpg --show-keys` in a
   scratch GnuPG home. It installs the key for apt (`/etc/apt/keyrings/hnx-docker.asc`) only when
   every primary key in the file has a fingerprint it could read, and each of those fingerprints is
   in `docker_engine_key_fingerprints`. The default is the vendor's "Docker Release (CE deb)" key,
   `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`. An empty file, an unpinned key beside the pinned
   one, and a key whose fingerprint cannot be read are all refused. The staging file and the
   scratch home are removed in every case. The repository root may be a lab mirror, so the key is
   never trusted because of where it came from.
4. **Adds the repository** (deb822 `docker.sources`, `Signed-By` the checked key) and **installs
   the pinned packages in one transaction**, then **holds** them:

   | Package | Pin (default) |
   |---|---|
   | `docker-ce`, `docker-ce-cli` | `docker_engine_version` (29.9.2) |
   | `containerd.io` | `docker_engine_containerd_version` (2.4.2) |
   | `docker-buildx-plugin` | `docker_engine_buildx_version` (0.38.1) |
   | `docker-compose-plugin` | `docker_engine_compose_version` (5.6.1) |

   Each pin is an upstream version. The packaging revision is the newest the repository serves for
   it (`<version>-*`). Each pin was at least 14 days old when it was set, and `tools/pin_freshness.py`
   watches them (see below for the engine). The install may change the held packages, so a bump is:
   set the new pin and re-run `main`. The holds are set again right after.
5. **Writes `daemon.json`** (`tasks/config.yml`): the json-file log driver, bounded to
   `docker_engine_log_max_size` x `docker_engine_log_max_file` per container. A new file is staged
   beside the live one and checked with `dockerd --validate`, and only then replaces it. A file
   dockerd refuses never goes live, because the daemon would not start. Replacing the live file
   leaves a restart owed (`<docker_engine_state_dir>/restart-pending`), and only a successful
   restart clears it. A failed restart, or `docker_engine_restart: false`, leaves the restart owed,
   and the next run retries it.
6. **Enables and starts** the `docker` unit.

A second run reports `changed=0`. This was proven on Debian 13 (trixie) against the vendor
repository: the first run made 10 changes, the second made 0, and readiness and health passed.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` | The unit is `active`, and `docker info` reaches the daemon (a server version, no server errors). |
| `health` | Readiness passes; the engine's `ServerVersion` equals the pin; the logging driver is `json-file`; `docker compose version` equals its pin; and `dpkg-query` shows every package at its pin and `hold`. |
| `upgrade` | Refuses a target that is not a newer `x.y.z` than `docker_engine_version`. Then set the pin and re-run `main`. |
| `backup`, `restore`, `export` | Nothing to do. The engine holds no data of its own, and each `compose_app` application backs up its own. |

## Notes

* **Pin freshness for the engine.** The vendor tags engine releases `docker-vX.Y.Z` on
  moby/moby, which `tools/pin_freshness.py`'s GitHub source does not parse. So the engine pin is
  listed as "not compared" and is checked against that releases page by hand. containerd, buildx
  and compose are compared automatically.
* **Key rotation.** Add the new fingerprint to `docker_engine_key_fingerprints` before the vendor
  switches. A key installed by an earlier run stays in place when a later run refuses the
  repository's key, so a refusal changes nothing on the host.
* **RL005.** `containerd.io` reads like a hostname. `tools/role_lint.py` skips a package name in a
  package-name context: the `docker_engine_packages` variable, and the `name` argument of `apt` and
  `dpkg_selections` ([docs/role-interface.md](../../../docs/role-interface.md) section 3).
