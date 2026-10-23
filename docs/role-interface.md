<!-- SPDX-License-Identifier: Apache-2.0 -->
# Role interface (version 1)

Every service role in HomelabNext implements one interface so that a role can be
swapped, health-checked, backed up, upgraded and exited without reading its
internals. The interface is enforced by `tools/role_lint.py`; the reference
implementations are `ansible/roles/example_service` (a plain service) and
`ansible/roles/compose_app` (a generic docker compose application).

## 1. Inputs: `meta/argument_specs.yml` is mandatory

Ansible validates the file natively, before any task runs. The linter requires:

* an `argument_specs` entry for `main` **and** for each hook below (entry points
  are tasks files, so `tasks_from: backup` is validated against `backup`);
* every option has `type` and `description`;
* `main` declares at least one `required: true` option. By convention it is
  `<role>_logical_id`, the service's id in the registry; it has no default;
* every key in `defaults/main.yml` is an option of `main`, and every optional
  option has a default (RL007).

## 2. Entry points (hooks)

| File | Contract | Idempotent | Mutates the service |
|---|---|---|---|
| `tasks/main.yml` | converge the service to the declared inputs | yes | yes |
| `tasks/health.yml` | fail unless the service is healthy now | yes | no |
| `tasks/readiness.yml` | fail unless every dependency is reachable | yes | no |
| `tasks/backup.yml` | declare/write what a backup must capture (a manifest) | yes | no |
| `tasks/restore.yml` | restore data from `<role>_restore_source` | yes | data only |
| `tasks/upgrade.yml` | validate a pinned version bump and record it | yes | state file only |
| `tasks/export.yml` | write the open-format exit copy to `<role>_export_dir` | yes | no |

Every task in a hook file carries the hook name as a tag (RL008), directly or
through an enclosing `block`, so `--tags health` works across all roles.
Invoke a hook with `ansible.builtin.include_role: {name: X, tasks_from: health}`.

A hook that cannot be implemented yet still exists and says so explicitly
(see the `hnx new role` scaffold); a missing file is a lint failure (RL003).

## 3. Defaults conventions

* Every variable is prefixed with the role name (`example_service_port`), RL006.
* No secret has a literal default (RL010). Secrets come from the secrets
  capability at run time.
* No IP literal anywhere in `defaults/`, `vars/`, `tasks/` or `templates/`, apart
  from loopback and the unspecified address (RL004), and no hostname literal in
  `defaults/`, `vars/` or `tasks/` (RL005). Variables whose name ends in
  `_image`/`_repository` are exempt from RL005 because they are covered by RL009.
* Container images are pinned by tag and `sha256` digest, never `:latest` (RL009).
  `compose_app` goes further: see section 6.
* A task that uses a secret-looking variable carries `no_log: true` (RL011). No
  `shell` or `raw`, and no `command` given a templated free-form string: use `argv`
  (RL012). TLS validation is never turned off (RL013). No privileged container or
  container-runtime socket (docker, containerd, podman, CRI-O) in `defaults/`, `vars/` or
  `templates/` (RL014).
* Versions are pinned; in real use they come from the registry row.

## 4. Service names come from the registry

A role refers to other services by **logical id** and resolves them at run time:

```jinja
{{ lookup('hnx_registry', 'query-core', field='url') }}   {# scheme://host:port #}
{{ lookup('hnx_registry', dep, field='host') }}           {# host / port / url #}
```

`ansible/plugins/lookup/hnx_registry.py` is a deliberately small stand-in that
reads the file named by the inventory variable `hnx_registry_file`
(`ansible/inventory/example/registry.yml`). The registry resolver replaces it
behind the same name and arguments. Moving a service changes the registry,
never a role.

Secrets are named the same way, by reference, and resolved on the controller only in a task
that carries `no_log: true`:

```jinja
{{ lookup('hnx_secret', wazuh_agent_enrollment_ref) }}   {# secret:siem/enrollment-password #}
```

`ansible/plugins/lookup/hnx_secret.py` reads `HNX_SECRET_<NAME>` (the registry's delivery
variable) or `<hnx_secrets_dir>/<name>`, and fails on a missing or empty secret. A role's
default may be a reference (`secret:<name>`), never a value.

## 5. Capability inventory groups

Playbooks target capabilities, not machines:

`cap_siem cap_lake cap_query cap_inference cap_edge cap_idp cap_secrets
cap_orchestration cap_broker cap_cases cap_tip cap_monitoring cap_decision
cap_nifi cap_sensor cap_scanner cap_backup`

`cap_sensor` (the network sensor), `cap_scanner` (the internal assessment scanner) and
`cap_backup` (the backup host, where restore drills run) are the product hosts of the centrally
applied baseline controls (ADR-0016 decision 7): their roles run once there and receive the
guests to enroll as `<role>_guests`.

Every capability also has a derived group, `cap_<capability>` with `-` as `_`
(`homelabnext.compute.model.group_for_capability`): for example `cap_context` and `cap_projects`
(the project-management tool's host, OpenProject in `docs/projects.md`).

`ansible/inventory/example/hosts.yml` shows the layout (hosts under the reserved
`example.internal` domain). Moving a capability to another guest is a group
membership change. `role_lint.py --playbook X --inventory Y` fails a playbook whose
`hosts:` names an inventory host or a literal address (PB001).

## 6. `compose_app` spec rules

`compose_app_spec.services.<name>` is validated before anything is rendered:

* `image` is the repository only (no tag, no digest); `tag` is mandatory and not
  `latest`; `digest` is mandatory and matches `sha256:<64 hex>`; the rendered
  reference is `repo:tag@digest`.
* The all-zero digest is a **placeholder**: refused unless
  `compose_app_allow_placeholder_digest: true` (development only; CI should never
  set it).
* `healthcheck.test` is mandatory for every service; `depends_on` entries must
  name services in the spec and render as `condition: service_healthy`.
* Logging is bounded (`json-file`, size and file count), restart policy defaults to
  `unless-stopped`, ports and secrets are never defaulted.
* Only the documented service keys are accepted, and every scalar is rendered
  JSON-quoted, so no value can add YAML of its own. The tag must match
  `^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`.
* Every service gets `security_opt: [no-new-privileges:true]` and `cap_drop: [ALL]`;
  `cap_add`, `user`, `read_only` and `mem_limit` are optional per service.
* Ports are always `host_ip:host_port:container_port`; nothing binds all interfaces
  by omission.
* Secrets never go in `environment` (a secret-looking key is refused unless it ends
  in `_FILE`). They go in `compose_app_secret_env`, which the role writes to
  `secrets/<service>.env` (mode 0600, `no_log`, no diff) and passes as an `env_file`.
* Every value is written with `$` doubled (`$$`), so docker compose never interpolates the
  deploy host's environment into the file, and a volume holding `$` or a source starting with `~`
  is refused outright (`${X:-/}:/host` is the host root once compose has read it).
* Bind sources are an allow-list: a host path is mounted only under `compose_app_bind_roots`
  (the application's own directory and data directory by default; never a host-wide directory
  such as `/etc`, `/var` or `/srv`) or when it is listed on its own, with a reason, in
  `compose_app_bind_extra` (`[{path, reason}]`). A `./relative` source, a named volume and an
  anonymous volume (a container path alone, `/var/lib/app`) need neither. Everything else (`/etc`, `/proc`, `/dev`, `/boot`, `/root`, `/run/systemd`, the D-Bus
  and buildkitd sockets, another runtime's state) is refused.
* A volume's bind source must be canonical (no `//`, no `.` or `..` component other than a
  leading `./`, no trailing `/`): compose passes `/.`, `//` and `/var//lib/docker` through
  unchanged and the kernel reads them as `/` and docker's state.
* A privileged container or a dangerous `cap_add`, a container-runtime socket or state
  directory (docker, containerd, podman, CRI-O; or host root, `/run`, `/var`) bind mount, and an
  explicit root `user` (the user or the group `root` or zero in any spelling: `0`, `00`,
  `000:0`, `root:root`; the root group alone, `1000:0`, needs `compose_app_allow_root_group`,
  for images built to run as an arbitrary uid in group 0) are refused unless
  `compose_app_allow_privileged`, `compose_app_allow_docker_socket` or
  `compose_app_allow_root` is set. A service with no `user:` runs as its image's default user,
  often root: set `user:` to a non-root id.
* `compose_app_allow_docker_socket` by itself lets through only the docker socket
  (`/var/run/docker.sock`, `/run/docker.sock`). Another runtime's socket or state directory
  (containerd, podman, a rootless `/run/user/<uid>/docker.sock`, `/var/lib/docker`) needs the
  flag and its own `compose_app_bind_extra` entry; host root, `/run`, `/var` and `/var/lib` cannot
  be listed, so they stay refused.

## 7. Linter rules

| Rule | Meaning |
|---|---|
| RL000 | invalid YAML |
| RL001 | `meta/argument_specs.yml` missing |
| RL002 | missing entry point / required input / `type`+`description` |
| RL003 | hook file missing or empty |
| RL004 | IP literal |
| RL005 | hostname literal |
| RL006 | variable not prefixed with the role name |
| RL007 | defaults and argument_specs disagree |
| RL008 | hook task not tagged with the hook name |
| RL009 | container image not pinned by tag and digest |
| RL010 | literal default for a secret-looking variable |
| RL011 | secret-looking variable used in a task without `no_log: true` |
| RL012 | `shell`/`raw`, or `command` with a templated free-form string |
| RL013 | `validate_certs: false` |
| RL014 | privileged container, container-runtime socket (docker, containerd, podman, CRI-O) or a bind source spelled with compose interpolation (`$VAR`, `${VAR:-/}`, `~`) in defaults/vars/templates |
| PB001 | playbook targets a hostname instead of a capability group |
| PB002 | play without `hosts:` |

Exit codes: 0 clean, 1 findings, 2 could not run. `python tools/role_lint.py --list-rules`
prints the table. The test suite carries a compliant fixture and one defect
fixture per rule (`tests/roles/fixtures/`).

## 8. Timers: `fleet_units`

Scheduled work is declared once and rendered, never hand-written:
`homelabnext/generators/fleet_units.py` renders `hnx-<name>.service` and
`.timer` from a list. Rules: `OnCalendar` only, every calendar ends in ` UTC`,
`OnBootSec`/`OnUnitActiveSec` (and the other monotonic triggers) are refused, the
output is byte-for-byte deterministic. The reason for the ban: with
`OnBootSec` + `OnUnitActiveSec`, a boot trigger point that passes while the unit
was not runnable leaves the timer `active` forever and never firing again.
`pages_directly: true` adds an `OnFailure=` page unit; `replaced_by: <ref>` renders the
unit disabled, with `ExecStart=/bin/false`, and marks it retired in `fleet-units.manifest`.

Every value must be a single line: a control character or a trailing backslash in any field is
refused, because either one lets a value add or swallow unit directives. Services are sandboxed
by default: without `user:` a unit runs as `DynamicUser=yes`, `user: root` needs
`run_as_root: true`, and every service carries `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, the kernel and cgroup protections,
`RestrictSUIDSGID`, `RestrictNamespaces` and an empty `CapabilityBoundingSet`
(`fleet_units.HARDENING`). `read_write_paths:` lists what the job may write under
`ProtectSystem=strict`; `hardening_opt_out: [Directive, ...]` drops named directives for one
unit, and shows up in review as exactly that.

### Every role timer reports its runs

A role (or profile) that ships its own `U.timer` + `U.service` makes the status hub's Schedule
page show the timer's last run, and whether it failed or is overdue, through one shared
convention: a **last-run record** per job per host
([`schemas/status/last_run.schema.json`](../schemas/status/last_run.schema.json), read by the
hub's `job-last-run` mapping, [docs/status.md](status.md#scheduled-jobs-last-run-records-job-last-run-registry-26)).

* The role's configuration includes role **`last_run`**, which installs the writer
  `/usr/local/libexec/homelabnext/hnx-last-run` (catalogued as `last-run-writer`) and the record
  directory (mode 0750, group `last_run_group`), before it writes its units:

  ```yaml
  - name: Install the shared last-run writer and the record directory (role last_run)
    ansible.builtin.include_role:
      name: last_run
    vars:
      last_run_dir: "{{ lynis_last_run_dir }}"       # default /var/lib/homelabnext/last-run
      last_run_group: "{{ lynis_last_run_group }}"   # default root: who may read the records
      last_run_writer: "{{ lynis_last_run_writer }}" # vars/main.yml, fixed
  ```

* Its service runs the writer on start and on stop, with the timer's own job id, `%n`, the
  timer's `OnCalendar=` value as written there and its `RandomizedDelaySec=` in seconds:

  ```ini
  ExecStartPre=-/usr/local/libexec/homelabnext/hnx-last-run start --dir {{ lynis_last_run_dir }} --group {{ lynis_last_run_group }} --job timer:lynis/scan --unit %n --calendar "{{ lynis_schedule }}" --delay 900
  ExecStopPost=-/usr/local/libexec/homelabnext/hnx-last-run finish ...the same arguments
  ```

  `ExecStopPost=` runs after a success, a failure, a timeout or a kill alike and gets systemd's
  verdict (`SERVICE_RESULT`, `EXIT_CODE`, `EXIT_STATUS`), so a failed run is recorded as failed;
  the `-` prefix means a writer problem never changes the job's own result. The record is written
  atomically, mode 0640, group `<role>_last_run_group`, at `<dir>/<job id>.json` (`:` and `/` as
  `-`). It carries the schedule the host actually runs, so lateness is judged without the
  repository.

* It says whether the job **ran**. What a scanner found stays with the role's health hook (the
  scan scripts still write their own `last-run` exit status beside their report).

Enforced: `homelabnext.status.maps.schedule.record_problems` lists every role or profile timer
whose service lacks either line, names another job, calendar or delay, or whose role does not
include `last_run`; the Schedule page shows those as problems and
`tests/roles/test_last_run.py::test_every_role_timer_writes_a_last_run_record` fails on any.
`hnx scripts reality` reads `ExecStartPre=` and `ExecStopPost=` beside `ExecStart=`, so the
writer's header must name every timer that runs it. A fleet unit (`fleet_units`) is not a role
timer and is not covered yet: its job id is `fleet-unit:<name>`, and the writer accepts it.

## 9. Scaffolds

`hnx new role|schema|capability|detection <name> [--dest DIR]` writes a minimal
artefact whose own checker passes (role: `role_lint`; schema: valid schema, one
example accepted, negatives rejected; capability: contract, fake and a conformance
test that the fake passes; detection: rule plus must-fire and must-not-fire fixtures).

## 10. SERVER-only

Running `--check --diff` of every role against a staging host (non-empty diff is a
red invariant) needs the server and is not implemented here; the roles are proven
by argument validation, strict-undefined rendering, hook execution on localhost
and `docker compose config`.
