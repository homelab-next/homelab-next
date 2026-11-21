<!-- SPDX-License-Identifier: Apache-2.0 -->
# Module `cti-pipeline`: threat-intelligence pipeline jobs, real and shadow, run by orchestration

A feature module (bundle `soc`, group `threat-intel`). It runs a site-built threat-intelligence app
(ingest, extraction, analysis, the CVE line, actor rotation, the site render, episodes) as
**module-owned job units** that the orchestration controller starts, one per job and lane:

```text
controller (exec runner) -> hnx-session-dispatch -> systemctl start --wait hnx-<id>@<job>-<lane>.service
                                                     (polkit: the controller's user, this set's units only)
     -> hnx-cti-run (as the lane's user, in the unit's sandbox) -> the job's steps, in order
```

The module never publishes. Every lane stages what it renders (`publishable/` under its root) and hands it
off to a per-lane directory ([Handoff](#handoff-to-the-publishing-module)); the publishing module owns all
egress to a public host. The shadow lane writes only its own lake schema
and its own lane root, so it can run beside the real lane (or before it exists) without touching
anything the real lane relies on.

**The run file (the dispatcher's contract v3).** PID 1 never reads it. The unit joins the
run-file group `hnx-<service>_<id>` (`SupplementaryGroups=`, created by the orchestration role; at
most 32 characters, so with the default service `orchestrator` the instance id is at most 15), and
`hnx-cti-run` opens `/var/lib/hnx-dispatch/<service>/<id>/%i.json` itself as the lane's user with
`O_NOFOLLOW|O_NONBLOCK`. It refuses anything but a regular file with one link that is owned by the
controller's user (`cti_pipeline_dispatch_owner`), writable by no one else and at most 256 KiB, so
a link, a directory, a FIFO or a hard link at that path is refused before anything is read. A
parse error (deep nesting included) is a refusal. The file's `version` (2), `job`, `lane` and
`unit` must be this instance's; its `run_id`, `agent_key` and `dispatch_id` (32 hex) must be well
formed; its `dispatched_at` must be within the 30-day keep window and at most an hour ahead. The
dispatch is then consumed: `<lane root>/hnx-consumed/<dispatch_id>` is created exclusively, and a
copied run file (the same dispatch) is refused. The dispatch is consumed before the release is pinned, so
a start refused after it ("the release went away") burns that dispatch; the controller's retry is a
new dispatch, so nothing is lost. The key is never the run id: the controller
reuses it across a run's retries and failovers, and each of those runs. Markers older than the
keep window are pruned (regular files named as a dispatch id, by lstat, never a link).

## Why job units, not sessions inside the controller

A controller session runs as the controller's user, in its cgroup and sandbox, and can read its
store (docs/orchestration-controller.md, "The trust boundary"). These jobs need their own writable
data root, several credentials and egress the controller does not have. So the session is a thin
trigger (the orchestration module's dispatcher) and the job runs under PID 1 in its **own** unit,
user, sandbox and credentials: no secret of the job ever enters the controller's cgroup,
environment or `/proc` view. Same-name runs serialise on the instance (the dispatcher locks it),
which replaces the old `flock` serialisation; the profiles' `min_context` / `exclusive` carry the
LLM sizing (the controller's admission), not this module.

## The artefact

The site builds the app once on the control host (never on the guest) and pins it:
`cti_pipeline_artefact` (its path) and `cti_pipeline_artefact_sha256`. It is a tar (gzip allowed):

```text
hnx-artefact.json   {"name": ..., "version": ..., "commit": ..., "packages": [...]}   (name and version required;
                    packages: the top-level packages a shadow-lane `{python} -m` may run)
app/                the application tree; the job's code, never written at run time
requirements.txt    optional: every wheel, pinned with --hash (built from the app's lock file)
wheels/             optional: those wheels, for the guest's Python and architecture
```

Install (`files/cti_artefact.py install`): the copy on the guest is hashed and **refused unless it
is the pin**, before anything is unpacked; only regular files and directories are unpacked (a
link, a device, an absolute or climbing path, a backslash, a control character, a repeated entry,
over 20 000 entries or 2 GiB: refused) into `releases/.<sha16>.incoming`; the venv is built there
offline (`pip --no-index --no-deps --require-hashes --only-binary=:all:` from `wheels/`; with no
requirement, a venv without pip); the pin is recorded in `.hnx-installed` and the directory is
then renamed to `releases/<sha16>`, given to root and the module's group (read only; nobody else
reads it) and `current` switched to it. A wrong or broken artefact never
touches the release in use. A second run with the same pin changes nothing. The venv is always run
as `venv/bin/python` (never a generated script), which is why the rename does not break it.
Releases past `cti_pipeline_keep_releases` are pruned (never the current one, and never one a job
runs: the wrapper resolves `current` once at start, rewrites `{app}` and `{python}` to that release
for the whole run, and holds a shared lock on its `.hnx-installed`; prune takes an exclusive,
non-blocking one and keeps a release in use for a later prune). An install that lands mid-job
changes only the jobs started after it.

## Jobs

`cti_pipeline_jobs` is role data (the overlay's), one entry per job:

```yaml
cti_pipeline_jobs:
  fresh:
    steps:                                  # argv lists, run in order in the lane root; the first failure ends the job
      - ["{python}", "{app}/run.py", "--stage", "ingest"]
      - ["{python}", "{app}/run.py", "--stage", "extract", "--extract-limit", "150"]
    timeout_s: 14400                        # the unit's TimeoutStartSec
    max_age_s: 7200                         # health: the last success is at most this old (0: not judged)
    lanes: [real, shadow]                   # default: every deployed lane
    env: {EXTRACT_MAX_BODY_CHARS: "48000"}  # merged over the lane's env
    refs: [FEED_USERNAME, FEED_PASSWORD]    # the lane secrets this job gets (default: all of the lane's)
```

A step's first element is `{python}`, `{app}/<path>` or an absolute path. Placeholders, replaced
whole in arguments and environment values by the wrapper: `{python}` (the current release's venv
python), `{app}` (its app tree), `{lane_root}`, `{config}` and `{lake_ca}` (the lab CA, when
`cti_pipeline_lake_ca_ref` is set). The working directory is the lane root, so an app that uses
relative `data/`, `state/`, `podcast/` and `dist/` finds its own lane's. That directory is the
lane's to write, so python must never import from it: the wrapper sets `PYTHONSAFEPATH=1` for every
step of both lanes (`-m <pkg>` and a script never put the working directory on the import path),
and neither the env nor a credential may set it or `PYTHONPATH`, `PYTHONHOME`, `PYTHONUSERBASE`,
`PYTHONSTARTUP`, `PYTHONINSPECT` or `PYTHONPLATLIBDIR`; the app imports from the release's venv only.

Each job and lane is one unit instance, `hnx-<id>@<job>-<lane>.service`: the template unit
(`templates/job.service.j2`) plus a drop-in per declared instance
(`hnx-<id>@<job>-<lane>.service.d/50-hnx-lane.conf`) naming the lane's user, the one directory it
may write (`ReadWritePaths=<data root>/<lane>`), its time budget and its credentials, and a job
spec per instance (`<config>/jobs/<job>-<lane>.json`, root's). The template alone runs nothing: the
wrapper refuses an instance with no spec. An instance the site no longer declares loses its spec
and its drop-in.

## Lanes: what keeps the shadow lane from publishing

| | real | shadow |
|---|---|---|
| user | `hnx-<id>` | `hnx-<id>-shadow` |
| writable | `<data root>/real/` | `<data root>/shadow/` |
| secrets | `cti_pipeline_lane_refs.real` files | `cti_pipeline_lane_refs.shadow` files only |
| lake schema (forced) | `cti_pipeline_lake_schema.real` | `cti_pipeline_lake_schema.shadow` (must end in `_shadow`) |
| publish mode (forced) | `stage` | `stage` |
| run files it can read | both lanes' (see below) | both lanes' (see below) |

Both lane users join the one run-file group the dispatcher's contract gives a set
(`hnx-<service>_<id>`), so while a real-lane run file exists the shadow lane's user can read it (its
`task` text; never a secret, and never consumable or changeable: the file is the controller's, the
marker directory each lane's own). A group per lane needs a later contract from the orchestration
module.

- The lake schema and the publish mode are **forced** into the environment last (the variable
  names are `cti_pipeline_lake_schema_env` and `cti_pipeline_publish_mode_env`, the app's own);
  the role refuses an env or a job that sets either, and refuses a shadow schema that does not end
  in `_shadow` or equals the real one.
- The role refuses, and the wrapper refuses again at every start, a shadow-lane job that runs a
  program off the allowlist below (its text could splice a name past any check), and one whose
  step arguments or env values name the real schema as a token: case-insensitively (a lake folds
  unquoted identifiers), after quotes, backticks and backslashes are deleted, bounded by white
  space, `= , : ; | < > +`, a dot (`cti.items`, `catalog.cti.items`), a quote, a backtick or a
  bracket. Only the module `{python} -m` names is exempt (code, not a table). A script file a step
  runs is not read: the grant below is what holds.
- A shadow-lane step runs only what is on an allowlist: `{python} -m <module>` or
  `{python} {app}/<script>` (no interpreter option before them), an `{app}/<path>`, or an absolute
  path the site lists in `cti_pipeline_shadow_programs` (default none). A shell, another
  interpreter, inline code or a command runner (`find -exec`, `xargs`, `timeout`, `nice`, `flock`,
  `script`) is never on it unless the site lists it. `{python} -m` runs only the app's own
  packages, `<pkg>` or `<pkg>.<sub>`: those of `cti_pipeline_shadow_modules`, or, when the site lists
  none, the artefact's `hnx-artefact.json` `packages` (none declared: no `-m` at all). The
  interpreter's own entry points (`timeit`, `pdb`, `cProfile`, `trace`, `http.server`, `runpy`,
  `code`) run code or commands taken from their arguments, so they are never allowed, and no
  interpreter module or installer (`pip`, `setuptools`, `ensurepip`, `wheel`) is ever accepted as
  one of the app's packages (the installer, the role and the wrapper all refuse it). Every
  `{app}/...` argument, once filled and normalised, must stay inside the release's app tree.
- The wrapper also refuses a shadow spec whose schema is not a shadow schema, any spec whose
  publish mode is not `stage`, and a run whose dispatcher lane differs from the instance's.
- **The lake grant is the real control; the environment is a convenience.** The forced variable
  is what the app is told, and the token check catches the obvious ways around it, but only the
  lake can make writing the real schema impossible. The shadow lane's lake credential must be one
  whose grants cover only `*_shadow` schemas (write) and, at most, read on the real one. The
  overlay's lake query user for the shadow lane enforces that; never give the shadow lane the
  real lane's lake credential.
- Each lane root is its user's alone (0700), so the shadow lane can neither write nor read the
  real lane's store; its credentials come only from its own lane's root-only files.
- Secrets are only ever in the module's own namespace (`cti-pipeline/` in the secret store): a publishing
  credential (another module's) cannot be given to a lane at all.

## Credentials

`cti_pipeline_lane_refs` maps each lane to `{NAME: <reference>}`, every reference in the module's
own namespace (`cti-pipeline/<name>` in the secret store). The role
writes each value to `<config>/credentials/<lane>/<NAME>` (root-only, 0600: the module's one
on-disk form), and the instance's drop-in loads it with `LoadCredential=NAME:<that file>`. PID 1
reads it as root and places it in the unit's private credentials directory; `hnx-cti-run` reads it
from there (every credential the unit loaded: the job spec holds no credential name) and exports
it **only into the job's step processes** (never a file, an argument or the log). A name is either
an env value or a credential, never both (the role refuses it, and the wrapper again at start). The
wrapper's log carries constants, the instance and counters only: nothing read from the spec, the
environment, the run file or a credential reaches it. A file the site no longer
declares is removed.

## Health, readiness

Readiness: systemd, an interpreter that can build a venv (`python3-venv`), the pinned artefact on
the control host, every secret in its form, and the gateway's and lake's registry rows when named.

Health (read-only): the current release is the pin; the wrapper, the template, every spec and
drop-in exist; the release imports the app (`cti_pipeline_import_check`); the gateway answers a
**real-sized** request (`cti_pipeline_gateway_probe_max_tokens`, at least what a job asks for)
with **non-empty content** (a reasoning model given a small budget spends it on thought and
returns nothing; HTTP 200 alone passes a broken tier); the lake query service answers over the lab
CA; and in each **active lane** (`cti_pipeline_active_lanes`: `[shadow]` during the shadow window,
`[real]` after the switch) every job with a `max_age_s` last ended ok within it. The wrapper writes
the record it judges, `<lane root>/hnx-runs/<job>.json` (`ok`, `exit`, `started_at`,
`finished_at`, the run id).

## Backup, export, restore

Export and restore run as root on a tree the lane's user owns, and that user runs code that reads
the internet, so neither ever follows a path the lane controls. Both first block the lane's units
(`systemctl mask --runtime` on each declared instance, then a wait, up to
`cti_pipeline_quiesce_wait_s`, until none runs; always unmasked afterwards): the dispatcher's start
then fails and the controller retries it later. The lane's units are the declared instances and any
other instance of the lane systemd still has loaded (a job the site just removed may still run). A
play that dies before it unmasks (the control node, the connection) leaves runtime masks: every
install lifts them (`systemctl unmask --runtime`, idempotent), and health fails while any job
unit is masked. While an export or restore runs, `<data root>/.quiesced-<lane>` marks its lane: an
install converging meanwhile (a scheduled deploy during a backup) leaves that lane's masks alone,
and treats a marker older than `cti_pipeline_quiesce_marker_max_age_s` as left by a play that died
(it unmasks the lane, warns and removes the marker). A marker not owned by the role's owner is
ignored, with a warning. **Health fails during a backup window**: the
lane's units are masked on purpose while the export runs.

An export (`hnx-cti-state/1`, `files/cti_state.py`) is a directory: `cti.db` (the store and its
`-wal` copied through descriptors that never follow a link, then made one consistent file by the
database's backup API and integrity-checked), `counts.json` (every table's rows), `files/<rel>` (every file
of the lane's `cti_pipeline_state_dirs`, the live store and its `-wal`/`-shm` excluded),
`listing.jsonl` (path, size, sha256) and `manifest.json`. It is built beside its name and renamed
when complete. The export hook writes `<data root>/export/<lane>-<stamp>/` for every lane that has
a store and keeps `cti_pipeline_keep_exports`. Every directory is opened relative to its parent
with `O_DIRECTORY|O_NOFOLLOW` and must be the entry that was listed (device and inode), every file
with `O_NOFOLLOW`; a link, a special file, a file with more than one link or an entry swapped
mid-walk refuses the export; the backup hook runs it and writes the backup
manifest (the configuration directory is not in it: it holds the secrets and is re-rendered).

Restore (`-e cti_pipeline_restore_source=<dir> -e cti_pipeline_restore_lane=real`), with the lane's
units blocked as above: the export is **checked first, writing nothing**: every file listed with
its size and sha256 and nothing unlisted, no link, the store's integrity check, and its row counts
**equal** to `counts.json` (and to `cti_pipeline_restore_expect_counts`, the source's own counts at
copy time, when given); a zero-table export is an error, never a pass. Then the store and the files
are staged in a root-owned sibling of the lane root, `<data root>/.restore-<lane>-<stamp>/` (the
lane's user cannot touch the data root), and given to the lane's user there; through descriptors
of the lane root and the stage, each replaced entry is moved aside as
`<dir>.before-restore-<stamp>` and the staged one renamed in (a rename never follows a link, so a
link planted in the lane root is only moved aside). Nothing is deleted.

Moving in from another host: run `cti_state.py export <its working tree> <dest> --include data
--include state --include podcast` there (the same layout as a lane root), copy `<dest>` to the
guest and restore it with the source's counts.

## The app contract (what the app must read)

- its lake schema from `cti_pipeline_lake_schema_env` and its publish mode from
  `cti_pipeline_publish_mode_env` (`stage`: write the site and episodes as publishable items under
  `publishable/`, never push);
- everything else it needs (the gateway's URL and model, the lake's URL and CA file, the feed and
  enrichment services, the notifier) from the lane env and the lane secrets;
- relative state paths (`data/`, `state/`, `podcast/`, `dist/`), which resolve in the lane root.

## What the overlay sets

- the selection: `cti-pipeline` (the instance id, a slug of up to 24 characters: it is the unit
  set's name) placed on a guest's `worker` role; `grants.egress.cti-pipeline.worker: [internet]`;
- `group_vars/mod_cti_pipeline_worker.yml`: `cti_pipeline_logical_id`, the artefact and its pin,
  `cti_pipeline_jobs`, `cti_pipeline_env`, `cti_pipeline_lane_refs`, `cti_pipeline_lake_schema`,
  `cti_pipeline_active_lanes`, the probes' registry ids;
- **the orchestration module's side, in the same change** (modules/orchestration README, "Module
  job units"): `orchestration_job_units: [{name: <cti_pipeline_logical_id>, jobs: {<agent key>:
  <job>, ...}, lanes: [...]}]` (every job named there must be one of `cti_pipeline_jobs`, in a lane
  it runs), `orchestration_runner_dispatch: true`, and one profile per agent key. If the
  orchestration module's run-file directory, user or job log directory differ from their
  defaults, set `cti_pipeline_dispatch_dir`, `cti_pipeline_dispatch_owner` and
  `cti_pipeline_job_logs_dir` to match;
- the secrets under `cti-pipeline/` in the secret store.

## Handoff to the publishing module

A lane root is its user's alone (0700), so what a lane stages in `<lane root>/publishable/` never
reaches the publishing module by itself. The handoff carries it, without widening any lane root:

```text
<lane root>/publishable/<kind>/<id>/        (the app's staged item: files + sidecar.json)
     -- after every step of a job succeeded, hnx-cti-run, as the lane's user -->
<handoff dir>/<lane>/<kind>/<id>/           (default /var/lib/hnx-handoff/<set>/<lane>/...)
     -- read by that lane's group only (publishing_gate_extra_groups) -->
publishing: publishing_gate_lane_sources [{lane, dir}] -> gated, STAGED ONLY under staging/lane-<lane>/
            publishing_gate_live_source {lane: real, dir} -> the one directory that is deployed (the switch)
```

* **Per-lane directory and group.** `<handoff dir>` is root's, `0711` (traversable, not listable). Each
  lane's directory under it is the lane user's, group `hnx-<set>-out-<lane>` (`cti_pipeline_handoff_group`),
  mode `2750`: the lane's own group reads it and nothing else does, so the shadow lane's items and the real
  lane's never share a path or a reader, and the shadow lane's user cannot read the real lane's. The
  groups are system groups this role creates; the publishing module's user joins the one it reads
  (`publishing_gate_extra_groups: [hnx-<set>-out-shadow]`), and the publishing module creates it too if it
  installs first (the order of the two modules does not matter). At the cutover the publishing user also joins
  the real lane's group and names its directory as `publishing_gate_live_source` (publishing's README, "The live
  source").
* **The item format is publishing's** ([its README](../publishing/README.md#an-item)): `<kind>/<id>/` with
  the files and `sidecar.json`. The handoff copies items whole and judges nothing about their content
  (the gate does): a new one is built beside as `.tmp-<hex>` (files `0640`, directories `0750`, whatever the
  unit's `UMask=0077`) and renamed in, so a reader sees all of an item or none. An item already handed off
  with the same bytes is left alone; **a changed item under a name already handed off is a conflict** and is
  never overwritten (a published id never changes); a symlink, hard link, device or an item with no
  `sidecar.json` is `refused`; entries that are not item directories (a `latest` link the app keeps) are
  `skipped`. **A conflict or refusal does not fail the job** (its work is done and the other items are
  carried): the counters go in the run record and the log (never content) and the **item ids** go in the run
  record (`handoff_conflicts`, `handoff_refused`). The **health hook fails** while the last run of any job in an
  active lane reports any (`cti_state.py handoff-health`), naming the ids. **To clear one:** remove the stale
  `<handoff dir>/<lane>/<kind>/<id>` (a conflict: the already handed-off copy no longer matches the lane's
  item), or fix or drop the unusable item in the lane's `publishable/` (a refusal); the next run of that job no
  longer reports it, and health passes. With `cti_pipeline_manage_accounts: false` the per-lane groups must
  already exist (the role asserts it instead of chowning to a missing group).
* **Pruning.** Handed-off items the lane no longer stages are pruned (the newest `cti_pipeline_handoff_keep`
  of them stay, nothing younger than an hour goes, half-built leftovers go after a day); what the lane still
  stages is never pruned (it would only be copied again). Only directories the wrapper made, directly
  under the lane's kind directory, never a link, are removed.
* **Nothing goes live from here.** The shadow lane's items are read by publishing as a stage-only source
  (publishing never deploys or uploads from it, in any mode). The real lane's directory stays unread
  until the cutover repoints publishing at it.
* `cti_pipeline_handoff_enabled: false` turns it all off (no directory, group or copy).

## Host preconditions

What the module needs on the guest and no module provides, with the check that fails clearly:

| Needs | Provided by | Check |
|---|---|---|
| the app artefact, a venv from `cti_pipeline_python` | this role (the artefact pin) | readiness: the pin, `import venv, ensurepip, sqlite3` |
| the dispatcher's user and run-file group | the orchestration role | readiness: `getent` |
| the `claude` CLI (the app's in-job fallback, D1: local model first) | **no module**: the site installs it | readiness, when `cti_pipeline_claude_cli` names a path: it must exist and `--version` must exit 0; the message says how to supply it. The path must be outside `/home` and `/root` (the units use `ProtectHome=yes`). Empty: the site does not declare the fallback |
| node, npm, wrangler | not needed here | the Pages deploy is the publishing module's, and only in `live` |
| the `hnx` runtime release | not needed here | the publishing module's (its readiness checks it) |

## Known limits (stated, not hidden)

- **No registry row.** The module serves nothing on a port; its health is the role's hook.
- **In-lab services with no slot.** The egress policy reaches the slots the module requires or
  prefers and the internet (global unicast only). An in-lab service that fills no slot (a feed
  reader, an enrichment service, a research service, a graph store) is neither, so under the
  egress policy those stages are dropped until such a service has a slot or a feature row this
  module can name.
- The units are never enabled: nothing runs a job but the dispatcher (or an operator writing a run
  file and starting the unit by hand).
