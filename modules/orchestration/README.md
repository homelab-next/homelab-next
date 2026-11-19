<!-- SPDX-License-Identifier: Apache-2.0 -->
# orchestration: the agent-session controller

Fills the `orchestration` slot (privileged, stateful) with this repository's own controller
(`orchestrator/cmd/controller`, ADR-0026; [docs/orchestration-controller.md](../../docs/orchestration-controller.md)).
It admits whole agent sessions: each job is one runner session, admitted against live backend
load, retried a bounded number of times, moved to another backend when it fails, and cancelled on
request, with capacity held only by live work.

| | |
|---|---|
| Slot | `orchestration` (adapter `homelabnext.conform.adapters.orchestrator:make`, features `admission`, `fault-injection`) |
| Registry row | `orchestration` (renamed to the instance the site selects), `protocol: http`, port 8088, `health: /healthz`, `metrics: /metrics` with a bearer credential, `auth: own`, **no public route** |
| Host role | `server`: one VM (2 vCPU, 2 GiB, 20 GiB by default), baseline `base` |
| Role | `role:orchestration`, hooks `main`, `health`, `readiness`, `backup`, `restore`, `upgrade`, `export` |
| Runner | `exec`, the controller's one built-in kind; the default command is a smoke session that needs no model |
| Egress | none declared; the controller calls nothing itself. A session reaches a model only through the gateway, and the events forwarder is a configured URL |

## Why a pinned binary under systemd, not the wheel and not a container

The controller is Go: the `hnx` wheel (role `hnx_runtime`) does not carry it (`MANIFEST.in` prunes
`orchestrator/`), so there is nothing for `hnx_runtime` to install. The lab-in-a-box builds it into
a container, but a container here would need a published image to pin by digest, and this repository
publishes none; building on the guest would put a Go toolchain and the network on a host that runs
agents. So the module follows the `hnx_runtime` model for a file: the binary is **built once on the
control host, pinned by sha256, copied to the guest, hashed where it landed and refused unless it is
the pin** (a wrong binary never touches the release in use: it is hashed under its own name first).
It then runs as the repository's own example unit, hardened (`ProtectSystem=strict`,
a seccomp filter, no capabilities, `TasksMax`/`MemoryMax`), under its own
system user, inside the module role's slice (`hnx_module_slice`). That unit is also the better
sandbox for the exec runner: the sessions the controller starts inherit the unit's filter, namespaces
and bounds, which a container's would not add to.

`make orchestration-binary` builds the pinned artefact (`build/hnx-controller`, static, `-trimpath`,
no VCS stamp, no build id) and prints its sha256. The same source and Go toolchain give the same
bytes, so the control host and CI agree on the pin; a different toolchain gives a different hash,
which is a new pin, never a silent change.

## What the role renders

| Path (defaults) | Content | Owner, mode |
|---|---|---|
| `/opt/hnx/orchestration/releases/<sha16>/controller`, `current`, `bin/controller` | the pinned binary and the links the unit runs | root, 0755 |
| `/etc/hnx/orchestration/controller.yaml` | the configuration, from the variables below | root:service group, 0640 |
| `/etc/hnx/orchestration/api-tokens.yaml` | each caller's **sha256 digest**, never a token | root:service group, 0640 |
| `/etc/hnx/orchestration/profiles/*.yaml` | the site's profile files (`orchestration_profiles_src`) plus, while the runner is the smoke session, the health check's one agent | root:service group, 0640 |
| `/etc/hnx/orchestration/homes/<backend>/` | the runner home of each backend; with a gateway, a `config.yaml` naming the gateway's URL and the backend's role alias, and the gateway key | root:service group, 0750 / 0640 |
| `/etc/hnx/orchestration/events.token` | the events forwarder's bearer token (only with a forwarder); the unit's `LoadCredential=` reads it as root and the controller reads the copy under `/run/credentials/<unit>/` at start | root, 0600 |
| `/var/lib/hnx-modules/orchestration/` | the data root: `controller.db`, `runs/`, `usage/`, `export/` | service user, 0750 / 0700 |
| `/etc/systemd/system/hnx-<instance>.service` | the unit | root, 0644 |

A changed binary, unit, configuration, home, catalog or events token **restarts** the controller
(it cancels its own running sessions on SIGTERM); a changed token file is **SIGHUP** (`systemctl
reload`, no restart); a changed profile set is `POST /admin/reload-profiles`. A converged host
restarts nothing (second run `changed=0`). Before any of it, the role runs the controller's own
`controller check` as the service user.

## Settings (the overlay's `group_vars`)

Required: `orchestration_logical_id`, `orchestration_binary` (absolute path on the control host),
`orchestration_binary_sha256`, `orchestration_profiles_src` (a directory of `*.yaml` profiles on the
control host). Everything else has a default; the ones that size the service:

| Setting | Meaning |
|---|---|
| `orchestration_concurrency` | jobs running at once over every backend (the admission pass is once a second) |
| `orchestration_backends` | the pool, in order (the first is the local backend): `{name, role, max_concurrent, max_context, weight, tags, needs_interlock, endpoint, health_url, load_probe_urls, context_length}` |
| `needs_interlock` (per backend) | calls to that backend take **one exclusive lease** (a lock file under the unit's runtime directory) released when the holder's session ends; `orchestration_interlock_wait_timeout_seconds` is how long a job waits for it before falling over to the next backend |
| `orchestration_api_max_unfinished_per_caller` | one submitter's queued + admitted + running jobs at most (a 429 past it); the API also refuses a caller's 2001st job in an hour |
| `orchestration_runner_timeout_seconds`, `_job_timeout_seconds`, `_stall_timeout_seconds`, `_max_turns` | the bounds of one attempt, a job's whole attempt chain, a stalled session and a session's model turns |
| `orchestration_orphan_grace_seconds` | how long a job may have no live executor before the orphan sweep ends it |
| `orchestration_tasks_max`, `orchestration_memory_max` | the unit's bounds over the controller **and every session together** |
| `orchestration_runner_argv` (+ `_usage_args`, `_toolsets_args`, `_exit_classes`, `_env_allowlist`) | the exec runner's command; **the default is the smoke session**, a real agent's command is the site's |
| `orchestration_runner_dispatch`, `orchestration_job_units` | the exec runner's command is the dispatcher, which runs each agent's session as its module's job unit ("Module job units" below) |

## Module job units: a job that runs as its module's own unit

A job that is a module's pipeline rather than an agent (a scheduled ingest, a site build, a
report) must not run inside the controller: a session shares the controller's user, its sandbox
and its `MemoryMax`, and can read `controller.db` ("Known limits" below). With
`orchestration_runner_dispatch: true` the exec runner's command is the **dispatcher**
(`hnx-session-dispatch`, installed beside the controller), which runs each session as a systemd
unit the module ships, under PID 1, in the module's own cgroup, user, sandbox and credentials:

```yaml
orchestration_runner_dispatch: true
orchestration_job_units:
  - name: cti                       # the unit set: units hnx-cti@<job>-<lane>.service
    jobs:                           # agent key (a profile's agent_key) -> job (the instance's first part)
      cti-hourly: fresh
      cti-publish: publish
    lanes: [real, shadow]           # default: both
```

| What | Where (defaults) | Owner, mode |
|---|---|---|
| the dispatcher | `/opt/hnx/orchestration/bin/hnx-session-dispatch` | root, 0755 |
| the run-file reader the job runs | `/opt/hnx/orchestration/bin/hnx-dispatch-read` | root, 0755 |
| the dispatch table (agent key -> set and job) | `/etc/hnx/orchestration/dispatch.json` | root:service group, 0640; the dispatcher refuses one owned by anyone else or writable by group or others |
| one polkit rule per set | `/etc/polkit-1/rules.d/49-hnx-<service>-<set>.rules` | root, 0644 |
| each set's group | `hnx-<service>_<set>` (a system group; at most 32 characters, so the set name is at most 32 - 5 - len(service); 15 with the default service `orchestrator`) | created by the role |
| the run directory of a set | `/var/lib/hnx-dispatch/<service>/<set>/` (parents root 0755) | service user : `hnx-<service>_<set>`, **2750** (setgid) |
| the run file of each instance | `/var/lib/hnx-dispatch/<service>/<set>/<job>-<lane>.json` | service user : `hnx-<service>_<set>`, 0640; removed when the run ends |
| the lock of each instance | `/var/lib/hnx-modules/orchestration/dispatch/<set>/<job>-<lane>.lock` | service user, 0700 / 0600 |
| the log file of each instance | `/var/log/hnx-jobs/<set>/<job>-<lane>.log` | root:service group, 0640 (directory root, 0750) |

**One session.** The runner gives the session `HNX_AGENT_KEY`, `HNX_LANE` and `HNX_RUN_ID`. The
dispatcher looks the agent up in the table, takes the instance's lock (a second session of the same
job and lane waits for it: same-name jobs run one after the other), refuses with exit 75 a unit it
finds already running (started by hand; classed `concurrency-limited`, a wait the controller asks
again after, unless `orchestration_runner_exit_classes` names 75), writes the run file, notes where
the unit's log ends, and runs `systemctl start --wait hnx-<set>@<job>-<lane>.service`. When the
unit ends it removes the run file and answers one JSON object: `outcome` (`done`, `failed`, `busy`,
`refused` or `cancelled`), `unit`, `result` and `exec_main_status` (from `systemctl show`, which
needs no polkit), and `log_tail`, the end (`orchestration_dispatch_tail_bytes`, 16 KiB) of what
**this run** appended to the unit's log. Success is exit 0 and the answer on stdout; a failed unit
is exit 1, the answer on stderr (the runner keeps stderr), and the unit's failed state is reset. A
cancel (the runner's SIGTERM to the session's group; any later signal is ignored) queues the stop
with `systemctl stop --no-block` (so the runner's kill grace cannot cut it off), waits up to 4 s for
it, resets a failed state, removes the run file and exits 143; a cancel while the session still
waits for the lock starts nothing. A systemctl call that hangs past 30 s is part of the answer, never
a traceback. An unknown agent, a lane the set does not run, a run id that is not
`[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, a task over 64 KiB (refused, never cut short) and an untrusted
table are exit 2 before anything is started.

**The module's log is the session's answer.** `log_tail` is stored by the controller with the job
(and shown to whoever reads the job): a module job must **never write a secret to its log**.

### The run file (the contract a module job implements)

The run file is read by **the job's own process, as the module's user** — never by PID 1, never
with `LoadCredential=` or `EnvironmentFile=`. (Root reading a path in a directory the controller's
user owns would let that user point a link at any file, directory or socket and have root read it
into the module's unit.) What a link or a planted file can reach is then only what the module's user
could read anyway.

* **Path**: `/var/lib/hnx-dispatch/<service>/<set>/<job>-<lane>.json` (`orchestration_dispatch_run_root`,
  then the controller's service id, `orchestrator` by default), i.e.
  `/var/lib/hnx-dispatch/<service>/<set>/%i.json` in the unit.
* **Access**: the directory is the controller's (`orchestration_user`), group
  `hnx-<service>_<set>` (the slugs hold no `_`, so the name is unambiguous), 2750; the file 0640,
  same group by the setgid directory. The module's unit gets read access with
  `SupplementaryGroups=hnx-<service>_<set>`; nothing else changes on the module's user.
* **Format** (contract v3, run file `version` 2): one JSON object, UTF-8, at most 256 KiB:
  `{"version": 2, "dispatch_id": 32 lower-case hex (fresh and random per dispatch), "run_id": str, "lane": "real"|"shadow", "agent_key": str, "job": str,
  "unit": "hnx-<set>@<job>-<lane>.service", "task": str (at most 64 KiB), "dispatched_at":
  "YYYY-MM-DDTHH:MM:SSZ"}`.
* **Validation, before anything is used** (all of it is `hnx-dispatch-read`):
  open with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK` (a link is refused, a FIFO never blocks), then on
  that descriptor `fstat`: a regular file, `st_nlink == 1`, `st_uid` the controller's uid, not
  writable by group or others, `st_size` at most 256 KiB; then the content: `version` 1, `job` and
  `lane` equal to the instance's (`%i` = `<job>-<lane>`), `unit` equal to the unit's own name,
  `run_id` matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, `agent_key` an agent key, `task` and
  `dispatch_id` matching `[0-9a-f]{32}`, `dispatched_at` `YYYY-MM-DDTHH:MM:SSZ` no older than the
  keep window (30 days) and no more than an hour ahead. A JSON error of any kind, nesting too deep
  included, is the same refusal. Anything else is refused and nothing more is read.
* **Replay**: the **dispatch id** (never the run id: the controller keeps a run's id across its
  retries and failovers, and each of those is a new dispatch that must run) is recorded as consumed,
  a marker created with `O_CREAT | O_EXCL | O_NOFOLLOW` in a directory of the job's own
  (`--consumed-dir`); a dispatch id seen before is refused. The dispatcher also removes the run file
  when the run ends (and on a cancel), so a start without a dispatcher finds none.
* **Pruning**: on each read, markers older than the keep window (`--keep-days`, 30) are removed
  (only regular files named like a dispatch id; a link is never followed). A run file dispatched
  before that window is refused, so a pruned marker never reopens a replay.

The reader the role installs does all of it and prints the checked JSON:

```ini
[Service]
Type=oneshot
User=<the module's own user>
SupplementaryGroups=hnx-<service>_<set>
# the job's first step, as the module's user: exit 1 and nothing read on any refusal
ExecStart=/bin/sh -c 'run=$(/opt/hnx/orchestration/bin/hnx-dispatch-read --dir /var/lib/hnx-dispatch/<service>/<set> --instance %i --owner hnx-orchestrator --consumed-dir <a directory of the job's>) && exec <the job> ...'
# opened by PID 1 before it drops to the unit's user, in a root directory the controller cannot
# write: the file the role made keeps its owner and mode, so the controller's group reads it and the
# controller is never in the journal's group
StandardOutput=append:/var/log/hnx-jobs/<set>/%i.log
StandardError=inherit
```

A module may implement the same checks in its own code instead of running the reader; the checks
above are the contract either way. The lane is the instance's last part; a unit picks its lane's
settings from it (an `env.real` / `env.shadow` of its own, say).

**The polkit rule** grants the service user (`orchestration_user`) the action
`org.freedesktop.systemd1.manage-units` with the verbs `start`, `stop`, `ref` (systemctl's
`start --wait` pins the unit with `Unit.Ref` while it waits, so its result stays readable) and
`reset-failed` on exactly the set's declared units, compared as whole names (never a prefix or a
pattern), and answers `NOT_HANDLED` to everything else, so polkit's default (authentication
required) applies: never `restart`, `reload`, `kill`, `set-property` or `clean`, never another unit,
never `manage-unit-files` or `reload-daemon`. The grant exists only with the dispatcher:
`orchestration_job_units` is refused unless `orchestration_runner_dispatch` is true (otherwise the
runner's sessions are arbitrary agent code holding it). The rule file is named by the service
(`49-hnx-<service>-<set>.rules`), so two controllers on one host do not overwrite each other's.
A rule this role wrote for a set the site no longer declares is removed (only a file whose **first
line** is the role's marker for this service); run directories and logs are kept. `remove.yml`
deletes the rules and the table. A host without `/etc/polkit-1/rules.d` refuses the job units.

Facts behind the design: a spike on a deployed controller (2026-11-19, a plain unit in a clone of
the controller's sandbox) proved that `systemctl start --wait` and `stop` reach PID 1 over the
system bus socket, which `ProtectSystem=strict`, `NoNewPrivileges` and the empty capability set do
not touch, that polkit names the caller by its uid, and that a unit the rule does not name is
refused. The rest is systemd's behaviour (read in its v257 source by the review), held here by
tests against a stand-in and not yet run on a host: the `unit` detail of a template instance is its
full name (`hnx-<set>@<job>-<lane>.service`, never the template), which the rule compares whole;
the verbs are `start`, `stop`, `ref` and `reset-failed`; a unit left failed starts again with
`start`; and a second `start` of a running oneshot merges into the first run's job (it would answer
the first run's result), which is why the dispatcher locks and checks `is-active` first.

**Settings.** `orchestration_runner_dispatch` needs `orchestration_job_units` and the reverse, and
the runner's own `orchestration_runner_argv`, `_usage_args` and `_toolsets_args` left at their
defaults (the dispatcher is the whole command); the health check's round trip does not run through
it (its agent has no unit), so `orchestration_health_job: yes` is refused with it. The controller's
unit gains `ReadWritePaths=` on its run directory (`<run root>/<service>`) when job units are
declared (a restart). Two controllers on one host declaring the same set get separate directories
and groups (and rule files); the unit names `hnx-<set>@...` and the log directory stay per set, so
those two would still share units: do not declare one set in two services.
`orchestration_job_logs_dir`, `orchestration_polkit_rules_dir`, `orchestration_dispatch_run_root`,
`orchestration_job_run_group`, `orchestration_dispatch_systemctl` and
`orchestration_dispatch_table_owner_uid` (0) exist for tests.

## Sizing a job: min_context and exclusive

A profile sizes its job with `backend_affinity`: `min_context` (a backend is eligible only when
its declared `max_context` is at least that; a backend that declares none fails it) and
`exclusive: true` (the run has its backend alone: it drains the backend and leases it once its load
reads 0). A backend's `max_context` must equal its gateway role's `max_context_tokens` (`hnx gen
gateway render --check` holds it); the window is raised on the role and the engine, never declared
larger than the engine serves.

`controller check` (run before every restart, and as the unit's `ExecStartPre`) refuses a profile
whose `backend_affinity` no configured local backend meets when the job has no cloud leg
(`local_only`, or no `backends.cloud`): such a job fails with no local capacity at every attempt, so
it would never run. That is a deploy-time refusal, not a job that silently never runs.

What this means for a module job (a pipeline whose own requests are sized per call, such as the
CTI rollups): set `min_context` to what the job's **largest local request** needs and that a
backend serves today, `exclusive` for a job that needs the pool to itself, and keep the decision
about a request that no local window can hold **inside the job**: it measures each request, runs it
locally when it fits, and sends only a real overflow to its own fallback, counting each one in its
log (which the dispatcher returns as the answer) for a watch to alert on. The controller's cloud leg
is not that fallback: with a module job unit the controller runs the unit, not the model calls.
A profile that asks for more than any backend serves (a 262144 window on a 131072 role, say) is
refused by the check until the role's window is raised.

## Profiles are data

The module ships no agent. `orchestration_profiles_src` is a directory on the control host holding
the site's profile files (`agent_key`, `toolsets`, `local_only`, `max_attempts`, prompt context,
`grants`, ...), copied as they are; a `*.yaml` the site no longer has is removed from the host (a
file only, directly in the profiles directory). An empty directory is refused, not served. Grants
need `orchestration_grants_catalog_src` (the render of `hnx mcp catalog render --client
orchestrator`); without it no profile may declare grants. `controller check` judges the whole set
before anything restarts.

## Callers, tokens and scopes

Four callers are fixed (their scopes are the controller's), more can be added with
`orchestration_extra_callers`. Each token is a secret of 32 to 256 characters of `A-Za-z0-9._~+/=-`
(no space: the broker's handler refuses one), distinct from every other caller's; only its sha256
reaches the host. Generate each with `openssl rand -base64 36 | tr '+/' '-_' | tr -d '\n='` and
store it in OpenBao at `secret/orchestration/<name>` (field `value`):

| Secret | Caller | Scope | Who holds it |
|---|---|---|---|
| `secret:orchestration/admin-token` | `operator` | admin | the operator's tooling and this role's health hook and profile reload |
| `secret:orchestration/jobs-token` | `broker` | jobs | the broker's `agent.job.submit` handler (`ORCHESTRATOR_JOBS_TOKEN`) |
| `secret:orchestration/status-token` | `status-hub` | read | the status hub's queue-summary poll |
| `secret:orchestration/metrics-token` | `metrics` | metrics | the metrics scraper (the row's `metrics.auth`) |
| `secret:orchestration/events-token` | | | only with `orchestration_events_forwarder_url` |
| `secret:orchestration/gateway-key` | | | only with `orchestration_gateway_id` |

A missing or malformed one fails `readiness` (and `main`) naming the form, before any file is
written. The API is bearer-authenticated; there is no unauthenticated mode here.

## Model calls: the gateway only

The controller sends nothing to a backend. With `orchestration_gateway_id` set (the gateway's id in
the registry), each backend's home gets a `config.yaml` whose `model.base_url` is the gateway's
registry URL and `model.default` the backend's **role alias** (`role:` in `orchestration_backends`,
required then, forbidden without). The role refuses a gateway that resolves to an IP address or to
plain http (without `orchestration_allow_plain_http`), and refuses any rendered value that names a
private IPv4 literal, WSL or `/mnt/<drive>/`: nothing here may depend on an operator's workstation.
A backend's `endpoint`, `health_url` and `load_probe_urls` stay on the engine (probes only, as the
docs say).

## Telemetry

* **Metrics**: `GET /metrics` (series `hnx_orchestrator_*`) needs the `metrics` scope; the registry
  row's `metrics.auth` names `secret:orchestration/metrics-token`, so the metrics module's generated
  scrape job sends it.
* **Events**: with `orchestration_events_forwarder_url` the controller emits
  `homelabnext.agent.job.finished` and `agent.job.failed` through its durable outbox, source
  `svc:<instance>` ([orchestration telemetry](../../docs/orchestration-telemetry.md)). The bearer
  token comes from `secret:orchestration/events-token` through a root-only file loaded as a systemd
  credential (never an environment variable, so it is not in the controller's `/proc/<pid>/environ`) and is
  never given to a session. Empty: events are off.
* **Status**: the status hub polls `GET /admin/queue-summary` with the read token (a status source
  the site adds to its copy of the row).

## Health, readiness

`health`: unit active; `/healthz`; no token refused; a jobs token refused on an admin route and on
`/metrics`; admin, status and metrics tokens each work; the token file on the host holds the
current digests (a rotation applied); and, while the runner is the smoke session
(`orchestration_health_job: auto`), a job submitted with the broker's token runs to `done` with the
session's answer. That round trip leaves one finished job row (a deviation from "health does not
mutate", stated in the hook). A real agent's command is never started by a health check.
`readiness`: systemd and `setpriv` on the host, the pinned binary and the profiles on the control
host, every credential in its form, the gateway in the registry.

## Backup, export, restore

The store is one SQLite file. `backup` and `export` write `export/{controller.db, jobs.jsonl,
listing.jsonl}` as the service user: a consistent online copy of the database, **every row as
jsonl** (the slot's neutral format: one `{"table", "row"}` per line), and a sha256 listing with row
counts; `backup` names only the data root in `backup-manifest.json`: the configuration directory holds the events token (`events.token`) and each runner home's `config.yaml` carries the gateway key, and it is re-rendered from the role's variables and the secret store by `install.yml`, so it is deliberately not in the file backup. A VM-level backup of the guest does carry them: protect that backup store accordingly. A
database that is not a controller store, or fails `integrity_check`, is an error, never an empty
export. `restore` (`orchestration_restore_source`) checks the export without writing (owner, modes,
a closed file set, single-link regular files, sizes, sha256, row counts, integrity, the job count),
stops the unit, installs only the database (staged, hashed as staged and integrity-checked;
the replaced store, with its `-wal` and `-shm`, is moved aside whole as
`controller.db.<YYYYMMDD>.before-restore` (a restore refuses when one exists, so it never overwrites
a kept store; delete it yourself when you no longer need it), then the copy is renamed into place, 0600), and starts the unit again whatever happened. On start the controller
reconciles: a job that was `running` becomes `failed` (never run a second time), `admitted` becomes
`queued`. The export holds task text and answers: it is owner-only, like the database.

## Upgrade

Build the new binary, then `playbooks/upgrade.yml -e orchestration_binary=<new> -e
orchestration_target_binary_sha256=<sha>`: the hook validates and records the bump, the store is
exported, then the role converges on the new pin (the old release is kept, `orchestration_keep_releases`).
A new controller whose schema must change refuses to start (exit status 3, not restarted); add `-e
orchestration_migrate=true` to migrate behind a backup in the same run (unit stopped, a new
`export/migrate-*.bak`). Roll back by pointing the pin at the previous release's sha256; a migrated
store needs its backup restored first.

## Known limits (stated, not hidden)

* **The API is plain http on the guest's address** (`tls: none`); bearer tokens cross the LAN in
  clear. The broker's `agent.job.submit` handler **requires https** for `ORCHESTRATOR_JOBS_URL`, so
  a TLS front (the edge on an internal name, or a terminating proxy on this guest) must exist before
  the broker can submit; the controller has no TLS of its own. This module does not ship one.
* **Sessions run as the controller's own user** (the exec runner; a module job unit run through
  the dispatcher is the exception: it runs as its module's user, under PID 1): they can read `controller.db`,
  other runs' directories and the runner homes (the gateway key). That is the controller's documented
  trust boundary until the agent runtime's unit launcher exists; run only agents whose output you
  would let read this host's controller state. What the unit does and does not give: the
  controller sets itself not dumpable (`PR_SET_DUMPABLE 0`), so a session cannot read its
  `/proc/<pid>/environ`, memory or descriptors, and it holds no secret in its environment (the
  events token is a systemd credential file; caller tokens are only digests); the empty environment
  allowlist keeps secrets out of a session's own environment. **It does not stop a session from
  reading files its user can read**: `controller.db`, other runs' directories, the runner homes (the
  gateway key) and the credential file under `/run/credentials/<unit>/`. `ProtectProc=invisible` is
  not a boundary between them (it hides other users' processes, and sessions share the controller's
  uid), so it is no longer claimed. A real boundary needs the sessions under another uid (the agent
  runtime's unit launcher, not built).
* **jsonl is export only.** The neutral copy leaves; the way back is the database copy. Importing
  jsonl into a controller is not built.
* `deadline` is not claimed: the job API takes no per-run deadline (the runner's job timeout is one
  value for every job).
* A session that makes the cloud re-run is not wired: the cloud backend is not configurable here
  (`local_only` profiles; cloud is a decision about the gateway's roles and TLP ceilings).

## Using it in a site (what the overlay adds)

The overlay carries every real value ([selection](../../docs/modules/selection.md),
[registry rows](../../docs/modules/registry-rows.md), [apply path](../../docs/modules/apply.md)):

1. **The binary**, built once on the control host: `make orchestration-binary` (static, trimmed,
   no VCS stamp or build id; prints the sha256). The overlay pins the path and the sha256
   (`orchestration_binary`, `orchestration_binary_sha256`); the role refuses any other bytes.
2. **A guest file** (`lab/guests/<name>.yml`): a VM, baseline `base`, resources covering the
   footprint (2 vCPU, 2 GiB, 20 GiB), `firewall_rules` admitting the broker, the status hub and the
   metrics scraper on tcp 8088 and SSH from the deploy host, and a `backup:` policy.
3. **The selection** (`lab/modules.yml`): `hosts.<name>: {guest: guest:<name>}` and
   `slots.orchestration: [{provider: orchestration, instance: <instance>, placement: {server: <name>}}]`.
4. **The registry row** (`lab/services.yml`): the module's `orchestration` row renamed to the
   instance, `host` the guest's name, plus the lab's own `standing`, `backup_job`, `scope`, and the
   status source (the read caller's secret) if the status hub polls `/admin/queue-summary`.
5. **The secrets**, by name: `orchestration/admin-token`, `jobs-token`, `status-token`,
   `metrics-token`; `orchestration/events-token` only with an events forwarder and
   `orchestration/gateway-key` only with a gateway. Only their sha256 digests reach the host.
6. **Grants**: `jobs-token` to the broker, `status-token` to the status hub, `metrics-token` to the
   metrics scraper (the credentials above marked `holder: granted`).
7. **The role's variables** (`group_vars/mod_orchestration_server.yml`): `orchestration_logical_id`,
   `orchestration_binary`, `orchestration_binary_sha256`, `orchestration_profiles_src`, and as
   wanted `orchestration_backends`, `orchestration_gateway_id`, `orchestration_events_forwarder_url`,
   `orchestration_grants_catalog_src`. No private address, WSL path or `/mnt` path is accepted.
8. **Apply**: `docker_engine` is not needed; the rendered `modules.yml` twice (the second
   `changed=0`), then `checks/orchestration.yml`, then the smoke session through the broker once the
   TLS front below exists.

## Conformance

`conformance/target.yml` binds the shared adapter; CI runs the whole suite strict, with process
fault injection, against this module's binary (`make orchestration-conformance`,
`tools/orchestration_conformance.py`). The adapter sends no token, so a run needs an
authentication-off controller on loopback: it cannot be pointed at a deployed instance, whose API is
authenticated and whose runner is the site's. `hnx modules check` holds the target to the slot's
adapter.

## Not yet: the TLS front for the broker

The broker's `agent.job.submit` handler requires an **https** `ORCHESTRATOR_JOBS_URL`; the
controller serves plain http on 8088 and has no TLS of its own. Until a front exists the broker
cannot submit, though everything else (health, metrics, the operator's admin calls from the guest
network, the exported store) works. Two options, not implemented here:

* **The platform's caddy edge on an internal name** (`modules/caddy`): a route
  `orchestration.<lab domain>` to `<guest>:8088`, certificate from the lab's internal CA, the
  row's `tls` changed to `internal` and `edge_tls.ca` naming the CA, with the broker host trusting
  that CA. One certificate story for the whole lab, the CA's renewal is already automated, and the
  firewall can then admit only the edge on 8088.
* **A local proxy on the guest** (a TLS terminator on 443 in front of the loopback port 8088): the
  controller could then bind loopback only, but this adds a second certificate lifecycle and a
  second unit to this module.

**Recommendation: the caddy edge on an internal name.** The lab already operates it and its CA, a
local proxy would duplicate both for one service, and the edge also lets the guest firewall shrink
to the edge alone. The cost is that orchestration depends on the edge being up for submissions,
which is acceptable (a failed submit is retried by the broker; running jobs are unaffected). The
change is a registry/overlay change plus a Caddy route, not a change to this role.
