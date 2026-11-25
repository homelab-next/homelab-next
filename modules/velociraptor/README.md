<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `velociraptor`: the endpoint-forensics provider

A provider module ([module manifest](../../docs/modules.md), draft; the SOC bundle of
[ADR-0049](../../docs/adr/0049-the-soc-data-plane-and-the-lab-checks-move-as-modules.md), decision 4
and plan step 12) that fills the new, provisional `endpoint-forensics` slot with
[Velociraptor](https://docs.velociraptor.app). It is a **service, not a machine**: the guests are the
site's guest files, and the site's selection places the module's two host roles on them: `server` on one
guest, `endpoint` on every guest or host the site wants hunted. Nothing here names a real host, address,
VM id or secret value; those live only in the private overlay.

**The server is an authority.** A hunt is not read-only by construction: an artifact can run commands and
write files on every client, so whoever may define artifacts holds, in effect, a root agent on the fleet.
This module's own principal therefore only **collects** (below), the manifest is human-approve, and every
action that changes an endpoint is a `remote-admin` broker action behind approval (ADR-0017), never this
module's.

| | |
|---|---|
| Slot | `endpoint-forensics`, provisional (no contract yet), stateful, export `object-tree` |
| Adapter | the shared read-only probe `homelabnext.conform.adapters.endpoint_forensics:make` |
| Product | Velociraptor 0.77.1, `ghcr.io/velocidex/velociraptor-server` pinned by tag and digest (built 2026-06-22) |
| Host roles | `server`: kind `vm`, baseline `base`, 2 vCPU, 4096 MB, 60 GB. `endpoint`: kind `vm`, baseline `base`, 1 vCPU, 256 MB |
| Roles | `velociraptor_server` (role interface v1, a wrapper of `compose_app`) and `velociraptor_client` |
| Requires | `cap:secrets` |
| Egress | none (the server downloads no tool; the endpoints fetch nothing: the controller fetches the release) |
| Public route | none |

## Ports

| Port | What | Proxied? |
|---|---|---|
| `velociraptor_server_gui_port` (default **8890**) | the GUI and its API, HTTPS with the server's own certificate, its own sign-in (`auth: own`). This is the module's **registry row** (`endpoint-forensics`) | a site may front it with its edge proxy (a `public_hostname` and the grants); the old fleet did, with the upstream's own origin override |
| `velociraptor_server_frontend_port` (default **8000**) | the **clients' port**: mutual-TLS speaking the product's own protocol, dialled by every endpoint | **never**. The clients pin the server's certificate authority and verify the server by name: a proxy in the way breaks every client. It is not a registry row (a provider's row is keyed by its slot, one per slot); the site's firewall file admits the endpoints' zones to it |

Both are published on the guest's own address only (`velociraptor_server_bind`, default the inventory's
`ansible_host`; all interfaces is refused). The API (gRPC) listens on the container's loopback and is
never published: the role and the hunt cycle reach it through `docker compose exec`.

## What the server role does

`roles/velociraptor_server` renders one `compose_app` service:

- **The configuration and its certificate authority persist and are never regenerated (LL-087).** The
  image's stock entrypoint regenerates the server configuration, and the authority in it, on *every*
  start, even with a persistent volume. Every enrolled client pins that authority, so one restart (a
  `docker restart`, a power cycle, a recreate) orphaned the whole old fleet four times (lessons LL-087,
  LL-213, LL-264) while the client list kept showing stale-but-populated rows, so the outage looked
  healthy. Here the container's command runs the stock entrypoint **only when
  `/etc/velociraptor/server.config.yaml` is absent or empty** (the first install); otherwise it starts the
  frontend directly and never touches the file. The configuration lives on the data volume (`etc/`).
  The role also records the **sha256 of the authority** (`state/ca.sha256`) on the first run and, on every
  later run and in `health`, **refuses to go on when the configuration's authority differs**, unless
  `velociraptor_server_accept_new_ca` says it is on purpose (a restore or a migration brings its own, and
  `restore` records the restored one itself). The behaviour was run against the real pinned image: the
  stock entrypoint rotates the authority on restart, the guarded command does not.
- **The first start downloads nothing** (`VELOCIRAPTOR_NO_INITIALIZE`): the module declares no egress, and
  the hunt principal can collect no artifact that needs a tool.
- **The container** runs as `velociraptor_server_uid:velociraptor_server_gid` (61100, an id no host
  account has) with every capability dropped and `no-new-privileges`, a memory limit, bounded logs and a
  healthcheck on both ports. The administrator's first password (`secret:velociraptor/admin-password`)
  reaches only the compose env_file (0600); only the first start reads it.
- **The module's artifact definition** (`Custom.Linux.Persistence.ConfigHunt`, read-only file reads and
  hashes, no command) is mounted read-only into the server's own definitions directory, so the server
  loads it at start and **no principal ever uploads one**. (The old definition read the loaded kernel
  modules by running `lsmod`: that is an EXECVE artifact, so this one reads `/proc/modules`.)

### The hunt principal collects; it does not run, write, define or administer

After the server generated its configuration, the role creates one API account,
`velociraptor_server_hunt_principal` (default `hnx-hunt`), and grants it **exactly** the permissions of
`roles/velociraptor_server/files/baseline-artifacts.yml`: `ANY_QUERY` (the API runs VQL),
`COLLECT_CLIENT`, `READ_RESULTS`, `START_HUNT`. **No `EXECVE`, `FILESYSTEM_WRITE`, `FILESYSTEM_READ`,
`ARTIFACT_WRITER`, `SERVER_ADMIN`, `IMPERSONATION`, `NETWORK` or `COLLECT_SERVER`.** The server reads its
accounts at start, so a new account or a changed policy is followed by one restart (which the start guard
makes safe, with the authority compared before and after). The principal's credential (`hunt.api.config.yaml`,
with a private key) lives on the data volume (`etc/`, 0600 the container's user) and is read only inside
the container; no agent profile, no secret in the store and no script argument ever holds it.

Verified against the real pinned server: as the principal, `execve` returns nothing, `artifact_set` (an artifact
upload) returns nothing, `collect_client` of an EXECVE artifact (`Linux.Sys.BashShell`) and of an IMPERSONATION
artifact (`Generic.Client.VQL`) is refused while a catalogued one (`Linux.Sys.Crontab`) and a hunt over it are
accepted, and the configuration's private keys are not readable from VQL. The `live`-marked test (below) runs
the role against the real image and covers the effective policy, `execve` and `artifact_set` through the
role's own `health`; the `collect_client` refusals were run by hand against a real enrolled client.

**The allow-list** (`baseline-artifacts.yml`, human-approve like every role file) catalogues the artifacts
the baseline hunt collects: `Linux.Sys.Crontab`, `Linux.Sys.SUID`, `Linux.Sys.Users`, `Linux.Sys.Groups` and the module's
`Custom.Linux.Persistence.ConfigHunt`. (The old baseline also collected `Linux.Sys.Services`; on the real
server its definition implies EXECVE, because it runs `systemctl`, so the principal cannot collect it and it
is not carried: the module's own artifact reads and hashes the unit files instead. The running-server check
found this the first time it ran against the real image.) Three layers hold it:

1. the file's own schema, in the script's `catalog-check` and the role's validate step: the principal's
   permissions must be inside the four, and no artifact may declare a permission outside them, so a change
   that adds an EXECVE artifact or widens the principal is refused before it is granted (a test per case);
2. every cycle and `health` compare each listed artifact's definition **on the running server**
   (`required_permissions` and `implied_permissions`) with the principal's rights: an upstream update that
   makes a listed artifact need EXECVE turns the cycle red and starts no hunt;
3. the server itself refuses what the principal does not hold (above).

**Anything that needs more** is not an entry here: it is a `remote-admin` broker action, one per kind of
change: `endpoint.quarantine`, `endpoint.remove-file`, `endpoint.kill-process` (ADR-0049 decision 4), held
by the broker's handler behind approval and never by an agent (ADR-0030, ADR-0045). The old memory
acquisition artifact (it runs a binary) is such an action and is not carried.

## The baseline hunt and the results the log pipeline reads

The server role installs `hnx-velociraptor` (`/usr/local/libexec/homelabnext/hnx-velociraptor`) and a timer
(`hnx-velociraptor-server-cycle.timer`, every `velociraptor_server_schedule`, default 5 minutes). Each run:

1. writes the **status file** (`<data root>/status/fleet.json`): the server answered, clients enrolled,
   clients heard within `velociraptor_server_stale_after_minutes`, the newest client's age, problems;
2. when none is due, starts nothing; every `velociraptor_server_hunt_interval_hours` (24) starts **one hunt**
   over the allow-list (the principal's `START_HUNT`); and
3. `velociraptor_server_collect_after_minutes` (60) after a hunt started, **collects** it once into
   **`<data root>/results/hunts/hunts-<hunt id>.jsonl`** (renamed into place whole, mode 0640, group
   `velociraptor_server_results_group`, inherited from the setgid directory; a file is never written through a link).

**The path for the log pipeline** (the `vector` module, `modules/vector/README.md`) is
`/var/lib/hnx-modules/velociraptor/results/hunts/*.jsonl` (the data root's default). A Vector agent on the
server's guest (the pipeline's sensor tier, which ships to the aggregator) tails that glob as a file
source and the site gives it the results group (`velociraptor_server_results_group`). One JSON object per
line, the module's contract (`endpoint_forensics.hunts`, the lake table the module owns and the novelty
analyzer reads, ADR-0036; the lake writer, not this module, writes it):

```json
{"time": "2026-11-22T03:00:00Z", "hunt_id": "H.XXXX", "artifact": "Linux.Sys.Crontab",
 "source": "CronTabs", "category": "cron", "client_id": "C.0123456789abcdef", "hostname": "host-a",
 "row": {"...": "the artifact's own columns"}}
```

A file is written once, whole, so the tail never sees half a hunt; a hunt id is a unique name, so a replay
rewrites the same file with the same content. The module does not delete results (retention is the
overlay's: the pipeline's job or a backup's). What counts as *new* since the last hunt (the baseline
diff the old fleet did in a script) is the novelty analyzer's job, not this module's.

## Capture-health criteria (ADR-0049 decision 8)

`invariants/criteria.yml` contributes three criteria, each running `hnx-velociraptor-check <name>` (a
`kind: check` script that only reads the status file):

| Criterion | Holds while |
|---|---|
| `velociraptor/service-up` | the last cycle reached the server, found no listed artifact needing more than collect rights, and had no other problem |
| `velociraptor/clients-enrolled` | at least `velociraptor_server_min_clients` (1) clients are enrolled |
| `velociraptor/clients-fresh` | the newest client was heard within `velociraptor_server_stale_after_minutes` (15) |

Exit 100 ("could not measure", never a pass) when the status file is missing, unreadable or older than three
missed cycles, so a dead timer is red. **Placement:** the check reads a file on the server's guest, so the
invariants runner that evaluates these runs there (or reads a copy of `status/fleet.json`: the script takes
the path as its second argument). A client list keeps each client's last-known state, so a rotated authority
still shows populated: `clients-fresh` is the test that notices, and `health` names the cause.

## Hooks

| Hook | What it checks or does |
|---|---|
| `readiness` (also the module's preflight) | `docker_engine` readiness, the inputs, the allow-list (permissions inside the four, no artifact needing more) and the administrator's password in its form |
| `health` | every container running and healthy; the authority is the recorded one (LL-087); `etc/` files are regular, 0600 and the container's; the clients' port serves the server's certificate and the GUI port answers 401 with no sign-in (both probed inside the container against its own authority); the principal's effective policy equals the allow-list's, it can read the fleet, it is refused `execve` and `artifact_set`; no listed artifact needs more than the principal holds on this server. It does **not** require an enrolled client (that is the criteria) and mutates nothing |
| `export` | `export/<UTC stamp>/{etc,datastore,listing.jsonl}`: the configuration (with the authority and the principal's credential) and the datastore, each file copied owner-only with its size and sha256 listed, the server **stopped** meanwhile and started again whatever happened; a new directory every run, nothing overwritten, nothing removed |
| `backup` | the export, then `compose_app`'s backup manifest (the data root, export included) |
| `restore` | the source is checked first without writing (a listing naming exactly the files present, each of its size and sha256, no link, no unlisted file), the server stopped, each tree built beside its target and renamed into place; a populated target is **renamed aside** (`<dir>.replaced-<stamp>`), never deleted. The restored authority becomes the recorded one |
| `upgrade` | refuses a target not pinned by tag and digest or from another repository, then records the bump |

The client role has the same hooks: `health`, `readiness`, `upgrade` real; `backup`, `restore` and `export` say
explicitly that the client keeps no data of its own.

## Secrets (names only; values live in the secret store)

| Secret | Holder | What |
|---|---|---|
| `secret:velociraptor/admin-password` | provider | the administrator's GUI password, set on the first start only |
| `secret:velociraptor/client-config` | granted | the client configuration the server generated (`client/client.config.yaml`): the authority, the dial addresses and the nonce, **no private key**. The overlay copies it into the secret store after the server's first run; the endpoint role reads it |

The server's own configuration (with the authority's private key) and the hunt principal's credential are
**not** in the secret store: they are generated on the server, live on its data volume (0600) and travel only
in the module's export and the backup. That is deliberate (LL-087): a secret store that could regenerate them
would be a second place to rotate the authority from.

## What the endpoint role does

`roles/velociraptor_client`: installs the **pinned release binary** (v0.77.1, sha256 pinned in the role; a
release without a pin is refused), the client configuration, a systemd unit, and waits for the client to
enrol.

- **The binary** is fetched by the **controller** (`get_url` with the sha256 checksum; the endpoints fetch
  nothing, which is why the module declares no egress) and copied to the host when the host's sha256 differs
  from the pin; a lab with no route to the release site gives its own copy
  (`velociraptor_client_binary_src`), still held to the pinned sha256. After the copy the installed file's
  sha256 is checked again.
- **The configuration is refused unless it is the real thing**: empty, text that is not YAML, no server
  URLs, a URL that is not `https`/`wss`, no authority certificate (a body of 200 or more base64 characters),
  no nonce, a placeholder (`REPLACE`, `CHANGEME`, `TODO`, `<`, `>`, `...`) or any `PRIVATE KEY` in it (the
  server's own configuration and the principal's credential carry one; a client's never does) all fail
  before a byte is installed. It is written 0600 root.
- **Enrolment is checked**: the role waits for the client's identity file (`client_id: C.…`) and fails when
  the unit runs but never enrolled (the usual shape of a wrong authority or address).
- The release must equal the server image's release; `velociraptor_client_version` and the server image are
  bumped together (the upgrade playbook does both).

## Client migration (from the old fleet's server)

The old server keeps serving the old fleet until a site decides otherwise; **never restart, recreate or
reconfigure it** (its certificate authority rotates on restart: lessons LL-087, LL-213), and never reuse its
configuration. The old and new authorities are **different**, so a client cannot simply be repointed: it
needs the new server's authority and address. The order, one endpoint at a time:

1. **New server first.** Install this module's `server` role. Wait for `health` to pass and the criteria
   `velociraptor/service-up` to hold. Copy `client/client.config.yaml` from the server's data root into the
   secret store, under the name in the secrets table above.
2. **Run both.** The old client keeps running, untouched. The new one runs beside it: the old unit is
   `velociraptor-client.service` with `/etc/velociraptor/client.config.yaml` and `/usr/local/bin/velociraptor`;
   the new role installs to the same paths by default, so on a host that still runs the old client set
   `velociraptor_client_install_path` and `velociraptor_client_config_dir` to a **second pair** of paths (for
   example `/usr/local/bin/velociraptor-hnx` and `/etc/velociraptor-hnx`), give the unit its own name
   (`velociraptor_client_service`) and, **essential**, give the client its own identity file
   (`velociraptor_client_writeback`, for example `/etc/velociraptor-hnx.writeback.yaml`): both configurations
   name the same default identity file, and two clients on one identity file would share a client id and keys
   across two authorities. Set all four in the site's group variables before the first run (the defaults
   would overwrite the old binary, configuration and unit).
3. **Enrol with the second config and verify.** The role waits for the new client's identity (written
   locally before the client reaches any server, so on its own it proves nothing) and, with
   `velociraptor_client_server_host` set to the server's inventory name, for the **server's own sighting**
   of that client id (`hnx-velociraptor client-seen`, delegated to the server). The client configuration the
   server role writes dials the **published** frontend port (`velociraptor_server_frontend_port`, e.g. 8001
   beside an old server on 8000), the same authority and nonce. Set `velociraptor_server_health_min_clients`
   once the fleet is enrolled, so the server's health counts enrolled, fresh clients. Then, on the new
   server, `velociraptor/clients-enrolled` counts it and `velociraptor/clients-fresh` holds, and the next hunt
   returns that host's rows in `results/hunts/`. Compare against the old server's view of the same host.
4. **Then remove the old.** Only after the new client has been fresh across at least one hunt: stop and
   disable the old unit on that host, and remove it from the old server's fleet by hand when the whole fleet
   has moved. The old server is retired last, by the operator, never by a role here.

A host with no route to the new server's address, or no egress to the release site (a contained detonation
host), uses `velociraptor_client_binary_src` with the pinned binary and gets its dial address from the
client configuration like any other.

## Upgrade

Bump the server image (tag and digest together, at least 14 days old; `tools/pin_freshness.py` watches it as
`role:velociraptor_server/velociraptor_server_image`) **and** the client release together
(`velociraptor_client_version`, with its sha256 added to the role's `velociraptor_client_checksums`), update
`product.version` and the lab registry's `version`, and run `playbooks/upgrade.yml`. The state is exported
first; the start guard keeps the configuration, so the new image cannot rotate the authority.

## What the overlay must add

- The selection: `endpoint-forensics` placed `server` on a guest (kind vm, baseline `base`) and `endpoint`
  on each guest to hunt; the guest files (the guest's firewall admits the endpoints' zones to the clients' port
  and the operators to the GUI port).
- Group variables: `velociraptor_server_frontend_hostname` (**required**: the name or address the clients
  dial, baked into the client configuration at the first start, so choose it first), the results group the
  log pipeline's agent runs as, and for the endpoints a per-host `velociraptor_client_logical_id`.
- The registry row (`endpoint-forensics`) exactly as bound, and the two secrets above in the store.
- The invariants runner placed on the server's guest, or a copy of the status file given to it.
- A Vector file source on the server's guest for `results/hunts/*.jsonl` (the `vector` module's sensor tier)
  and a lake-writer table `endpoint_forensics.hunts`.
- `grants`: none for this module's own egress (none declared). The GUI's edge route, if the site wants one, needs
  `grants.public_routes` like any row.
- A **conformance** config for the probe: `ca_file` (the authority from the client configuration, written to a
  file) and `server_name` (the name the server's certificates are issued to; the probe verifies both ports'
  certificates under it and never with verification off).

## Tests

`tests/modules/test_endpoint_forensics_*.py` and `tests/roles/test_endpoint_forensics_*.py` (the slot's name, not
the product's), including the proof that the hunt principal is refused an EXECVE artifact and an artifact
upload. The tests marked `live` need Docker and the real pinned image and never run in the default CI job.
