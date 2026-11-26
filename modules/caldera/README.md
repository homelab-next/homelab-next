<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `caldera`: adversary-emulation control validation on an isolated guest

A feature module ([module manifest](../../docs/modules.md)) that runs the
[Caldera](https://github.com/apache/caldera) adversary-emulation server (the Apache project MITRE
donated it to) as **one compose_app container**, built on the guest from a pinned source tag,
because no prebuilt image exists. It is **not a slot provider** and has no conformance target. It
only packages the tool: which targets an assessment touches, and when, is the operator's.

**Scope:** lab-internal adversary-emulation control validation, detection testing and security
research. Use outside the lab requires explicit permission.

| | |
|---|---|
| Kind | feature, no slot, no registry row, no public route, no SSO, no reverse proxy |
| Product release | 5.3.0 (`caldera_version`), its commit pinned too (`caldera_source_commit`) |
| Host role | `server`: kind `vm`, **exposure `isolated`**, baseline `base`, footprint 2 vCPU, 4 GB, 40 GB |
| Role | `caldera` (role interface v1), a wrapper of the core `compose_app` |
| Requires | `cap:secrets` (the two passwords, read by name at deploy time) |
| Egress | install and upgrade only, optional (see Egress) |

## Placement: an isolated guest, and only one

**Placement is deferred: pm200 VLAN 40 (the isolated research network), after old-lab retirement.** The module is placement-agnostic: the overlay adds the host when that network exists; nothing here names a guest, address or VM id.

The module's host role declares `exposure: isolated`, so the loader **refuses the selection** unless
the host it lands on is marked `isolated: true` by the site ("an isolated role lands only on an
isolated host, and only it does": `hnx modules check` fails, `render` produces nothing). The
overlay's placement is the guest on **VLAN 40**, the isolated research network; the module itself picks no VLAN, address or VM id. A guest that is not isolated, and a
public exposure, never get this role. The generated network policy gives an isolated role no egress
at all while it runs (its chain accepts nothing and drops everything), which is the run-time
posture: the server opens no connection of its own.

## What the role does

- **Source.** `git clone` of `https://github.com/apache/caldera.git` at the tag `caldera_version`
  into `<data root>/src` (depth 1, with the plugin submodules, `force` so a local edit to a tracked
  file is reset). The checked-out `HEAD` must equal `caldera_source_commit`: a tag that moved is
  refused before anything is built. `conf/local.yml`, `data/` and `logs/` are gitignored upstream,
  so a re-clone never touches them.
- **Image.** `docker build` of the tree's own Dockerfile (variant `full`, so the offline atomic and
  emulation libraries are baked in), tagged `localhost/hnx-caldera:<version>` and labelled with the
  commit. It is built only when no image of that tag and commit exists (`caldera_rebuild` forces
  it), so a re-run changes nothing. compose_app pins by digest: the role reads the build's digest
  and refuses to go on if the daemon cannot resolve it as a reference (the daemon must use the
  containerd image store, Docker's default). The first build is slow (UI build, packages, two
  public repository clones, payload downloads).
- **The compose deviation from upstream (a real bug).** Upstream's `docker-compose.yml` bind-mounts
  the whole source tree over `/usr/src/app`. That shadows `plugins/magma/dist`, the UI the image
  build baked in (a build artefact, not tracked in git), and the server dies at start with
  `FileNotFoundError: plugins/magma/dist does not exist` (hit for real on the old lab's first
  deploy). This module's compose spec mounts only what must outlive a restart: `src/conf`,
  `src/data` and `src/logs`. A test holds that.
- **Configuration regenerated at every converge.** Upstream writes `conf/local.yml` with random
  credentials at first boot and logs them to stdout. This module writes it instead, every run, from
  the secret store: the `admin` and `red` accounts (both in the red group) get the passwords of
  `caldera_admin_login_ref` and `caldera_red_login_ref`; a password changed in the UI does not
  survive the next converge. The file is 0600 and rendered in a `no_log` task. The container is
  restarted when the file changed (the server reads it once). The blue-team account is not
  provisioned. The other values the server wants (API keys, the salt and key its stored data is
  encrypted with, two contact passwords) are generated once into `<data root>/seed/` (0600,
  never replaced) and are not secret refs: nothing outside the host needs them.
- **The container** runs with every capability dropped and `no-new-privileges`, a memory limit, and
  bounded logs; the image runs the server as root inside the container, which compose_app allows
  when no user is set. Only **8888** (the UI and the HTTP agent contact share it) is published, on
  the guest's own address (`caldera_bind`, default the inventory's `ansible_host`; all interfaces is
  refused). `caldera_extra_ports` (`7010/tcp`, `7011/udp`, ...) publishes other agent contact
  ports; the default is none.

## The secrets

| Secret (default name) | Holds |
|---|---|
| `caldera/admin-password` | the admin account's password (12 or more printable characters) |
| `caldera/red-password` | the research account's password (12 or more, different from the admin's) |

Both are read in `no_log` tasks by `hnx_secret` and checked for their form in the readiness hook;
neither is written anywhere but `conf/local.yml`. Rotating one is changing the secret and
converging: the file is rewritten and the container restarted.

## Egress

Install and upgrade need the internet: the pinned clone from github.com, and the image build's own
fetches (the base images, apt and npm packages, pip, two public repository clones and the emulation
payloads). That is declared in the manifest as one **optional** entry for the `server` role
(`to: [internet]`): a site that grants nothing gets the module with no such egress, one that lists
`internet` under `grants.egress.caldera.server` opts in, and then removes the grant after the
install, as the operator-owed rules below say. The build runs in the docker daemon and the clone in
the deploy's own process, outside the role's slice, so the isolated role's run-time policy (which
drops all of the role's own traffic) does not stand in their way; what stands in the way, or not, is
the guest's own firewall, which the site opens for the install and closes after. The running
server opens no connection: its egress is `none` in effect.

## Why `app.contact.http` names `0.0.0.0` port 8888 with the HTTP scheme, and how to deploy an agent anyway

The generated configuration has `app.contact.http` set to the HTTP scheme, `0.0.0.0` and port 8888. That is **not a bug to fix
in the file**: `0.0.0.0` is the container's own correct bind address, inside its network namespace,
and the container uses ordinary Docker bridge networking (not host networking), so the guest's
address does not even exist inside it to bind to. Docker's own `8888:8888` mapping is what makes the
service answer at the guest's address. The old lab's research host carried the same line for the same
reason, and found that no edit sticks anyway (the server resets it at every restart).

The rough edge is cosmetic and only in the UI: the "deploy an agent" one-liners echo
`app.contact.http` verbatim as the callback address. **When you copy a generated deploy command,
replace the embedded `0.0.0.0` with the guest's own address by hand** (the one in the overlay's
guest record, the one the UI is reached at), and never try to "fix" `local.yml`. The same goes for
any contact port you publish with `caldera_extra_ports`.

## Hooks

| Hook | What it checks or does |
|---|---|
| `main` | validates, checks the credentials, creates the data directories, clones the pinned source, builds the image when needed, writes the configuration, renders and starts through compose_app, restarts on a changed configuration |
| `readiness` | the container engine is ready and both passwords resolve in their form (preflight) |
| `health` | the container is running and healthy; the authenticated health endpoint (the generated API key) reports the pinned release; the admin and the red account each sign in with the password in the secret store |
| `backup` | writes a fresh export, then names the data root for the guest's backup |
| `restore` | checks an export snapshot, stops the server, stages each listed file beside its target and renames it into place, starts the server again whatever happened |
| `upgrade` | validates a newer release and its 40-hex commit and records it as pending; the playbook exports, then converges (re-clone, commit check, rebuild) |
| `export` | writes the open-format exit copy (below) |

Run an upgrade with `-e caldera_target_version=<x.y.z> -e caldera_target_commit=<40 hex>`
(`git rev-parse <tag>^{commit}`); it needs the install-time egress again.

## Data

Four datasets, each kept forever: the operations (and their results), the adversaries (with
abilities and objectives), the agents (and the server's agent and payload settings), and the
artifacts (payloads, fact sources, collected files). They live in the source tree's `data/` and
`conf/` under `<data root>` (`/var/lib/hnx-modules/caldera`). The export
(`export/<stamp>/files/<key>` plus `listing.jsonl`: key, size, sha256, dataset) is written by
`files/caldera_tree.py`, staged in a sibling directory and renamed into place, regular files only,
never overwriting or deleting an earlier snapshot; the restore refuses a traversing key, a link, a
second hard link, an unlisted or altered file and an empty listing before it writes. The
operations and the agent registry are one pickled file (`data/object_store`) that the server saves
itself, **encrypted with the key in `seed/`**: the exit copy deliberately holds neither the seeds
nor `conf/local.yml`, so it is safe to hand around, and the encrypted object store inside it opens
only on a data root that kept the seeds. The guest's backup of the whole data root carries the
seeds; keep it that way.

## Operator-owed, in the overlay

1. **The guest and its placement**: a guest on VLAN 40, marked `isolated: true` in the selection's
   host, with the module's `server` role placed on it (and `docker_engine` applied first).
2. **The secrets** `caldera/admin-password` and `caldera/red-password` in the secret store.
3. **VLAN 40 rules**: this guest may reach **named assessment targets only** (addresses on the range
   VLAN, authorised per exercise), nothing on any production VLAN, and the internet only for the
   install or upgrade (the clone and the build's fetches), closed again after. Operators reach the
   UI, and agents on the targets reach the contact port, by the guest's own address; those inbound
   rules are the network model's, not the module's.
4. **The grant** `grants.egress.caldera.server: [internet]`, only for the install or upgrade
   change, deleted with it.
5. Group variables for `mod_caldera_server`: `caldera_logical_id`, and `caldera_extra_ports` if an
   exercise needs another agent contact port.

## Known limits

- The image is built on the guest, so it is not reproducible to the byte; the pin is the source
  commit, and the digest is read after the build.
- The first build needs memory and time (the UI build alone is node); the container's 4 GB limit is
  for the running server, not the build.
- There is no TLS and no SSO: access is the guest's own address on an isolated VLAN, the same
  posture the old lab's server held.
- A converge resets edits to tracked files in the clone (`force`), including a `conf/agents.yml`
  changed in the UI; the export keeps the changed copy, so take one before an upgrade (the upgrade
  playbook does).
