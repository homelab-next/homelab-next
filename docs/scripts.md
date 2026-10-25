# Scripts: header, catalog and the checks that keep it true

Every script in the tree carries a small machine-readable header. The headers generate the
[script catalog](scripts/catalog.md) ([JSON](scripts/catalog.json)), and three checks keep the
catalog honest (checklist section M):

| Row | Command | Fails when |
|---|---|---|
| M-01 | `hnx scripts catalog --check` | a script has no header or an invalid one, two scripts share an id, or the committed catalog differs from what the headers produce now |
| M-02 | `hnx scripts reality` | something runs a file that has no header, a scheduled exec resolves to no catalogued script, an active script has no caller, or a header's `trigger` list differs from the callers found in the tree |
| M-04 | `hnx scripts runner-lint` | a `kind: check` script is not run by the invariants criteria its header names, a criterion runs a script that is not marked as a check, or a timer runs a check directly |

All three run in `make check` (`make scripts-check`), in CI (`schemas` job) and as the criteria
M-01, M-02 and M-04 of the [invariants register](../examples/registers/invariants.yml). Exit codes:
0 ok, 1 findings, 2 usage error or an unreadable allowlist. `hnx scripts list [--json]` prints the
entries; `hnx scripts catalog` rewrites the two catalog files (commit them with the header change).

## What counts as a script

A script is a file that is executed as a program rather than imported:

* every `*.py`, `*.sh` and `*.bash` file, every `*.py.j2` and `*.sh.j2` template (a script a role
  or profile installs on a host), and every file that starts with `#!`;
* **except** these classes, which are not scripts:

  | Path | Why |
  |---|---|
  | `homelabnext/` | package modules: run through `hnx` or `python -m`, never as files; the CLI's `COMMANDS` table is their catalog |
  | `tests/`, `tools/tests/` | test code: pytest imports it |
  | `conformance/` | suites, protocols and fakes the suites import |
  | `ansible/plugins/` | Ansible loads plugins; nothing executes them |
  | `examples/codemode/*/prelude.py` | a profile's generated Code Mode runtime prelude (`hnx codemode gen`): source the runner rebuilds and its executor runs inside a program's sandbox, never a file run |
  | `conftest.py`, `setup.py` | pytest configuration and the build backend's hook |

* **plus** any file in those classes that something runs as a program. A fake under
  `conformance/fakes/` that a compose service starts is a script there: it carries a header, and
  `hnx scripts reality` reports a run file that has none.

The tree is `git ls-files` in a checkout (a directory walk elsewhere), so scratch files are not
scripts until they are tracked.

## The header

A YAML block in comments, introduced by the exact line `# hnx-script:` within the first 40 lines
(after the shebang, the SPDX line and any usage comment). Every following line that starts with
`#` and at least two spaces belongs to it; the first line that does not ends it. The schema is
[`schemas/platform/script_header.schema.json`](../schemas/platform/script_header.schema.json).

```text
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# hnx-script:
#   id: hermetic-lint
#   kind: check
#   purpose: Fail when test code reads the wall clock or unseeded randomness directly.
#   owner: maintainers
#   trigger: [ci:ci/lint, make:hermetic-lint]
#   invariant: [Q-11]
#   inputs: every .py under tests/ and tools/tests/ (or the files named)
#   outputs: one line per finding
#   exit:
#     "0": clean
#     "1": findings
"""Gate: test code reads neither the wall clock nor unseeded randomness directly."""
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | unique slug, the catalog key |
| `kind` | yes | `check` decides whether a standing property of the repository or the platform holds (exit 0 = it holds); `tool` is run by a person, a make target, CI or another script for one run's purpose; `job` is a one-shot task an orchestrator starts; `service` is a long-running process |
| `status` | no | `active` (default) must have a caller; `deprecated` may have none |
| `purpose` | yes | one sentence |
| `owner` | yes | a team or area slug, never a person |
| `trigger` | yes | every caller, in the grammar below, exactly as `hnx scripts reality` finds them; `manual` for a person |
| `inputs`, `outputs` | yes | a sentence or a list |
| `exit` | yes | exit-code contract, code to meaning; `0` always documented. A check also documents a failing code in 1..99, because the invariants runner reads 1..99 as fail and 100 or more as could-not-measure |
| `invariant` | checks only | the criteria ids that run it |
| `installs_to` | no | the absolute path a role installs it at, so a unit's `ExecStart` resolves to it |

## Triggers: callers are discovered, never declared

`hnx scripts reality` finds every caller in the tree and compares the set with the header's
`trigger` list, both ways: a caller missing from the header and a trigger nothing backs are both
findings.

| Trigger | Found where |
|---|---|
| `make:T` | a recipe line of target `T` in the root `Makefile` names the script (simple variable assignments are expanded) |
| `ci:W/J` | a `run:` step of job `J` in `.github/workflows/W.yml`; a workflow with `on: schedule` is a timer |
| `pre-commit:H` | the `entry` of hook `H` in `.pre-commit-config.yaml` |
| `compose:S/V` | service `V` of the compose stack in directory `S` runs it (`command`/`entrypoint`, mapped back to the repository through the Dockerfile's `COPY` lines) |
| `script:I` | catalogued script `I` names it on a non-comment line |
| `code:P` | package module `P` loads it with `paths.checkout_tool("NAME")` |
| `fleet-unit:N` | entry `N` of a fleet_units spec (`fleet_unit_specs` globs) execs it: a timer |
| `timer:R/U` | role `R` ships `U.timer` and `U.service`, and the service's `ExecStart` runs it: a timer |
| `role:R`, `profile:P` | a task file of role `R` (any YAML file of profile `P`) names a script shipped inside it |

An `exec`/`ExecStart` resolves to a script through its `installs_to` path or by ending in the
script's repository path; `hnx` itself is the platform's entry point. A scheduled exec that
resolves to neither is a scheduled job nobody catalogued, and fails M-02 unless
`external_exec` names it with a reason.

Invariant criteria are found the same way: a criterion runs a script when its `observable` names the
script's path, or, for a plugin criterion, when a string in the registered check function's body
does (comments and docstrings do not count). M-04 compares that with the header's `invariant` list.

## Checks run in one place

A `kind: check` script runs through the invariants runner: a criterion's observable (or plugin)
runs it, and the platform schedules `hnx invariants run`, which pages once on a newly red
criterion (L-03). A timer, fleet unit or scheduled workflow that runs a check directly fails M-04:
such a check pages on its own terms, and the one page that says whether every invariant holds no
longer knows about it. CI and make targets may still run a check directly; they gate a change,
they do not watch the fleet.

## The reviewed allowlist

[`tools/scripts.allow.yml`](../tools/scripts.allow.yml) holds the settings (which invariants
registers and fleet_units specs to read) and three lists, each entry a script id (or an exec path)
with the reason:

* `uncalled`: an active script with no caller in the tree (an operator runs it by hand);
* `not_in_runner`: a check that no criterion runs;
* `external_exec`: a scheduled exec that is a product binary, not a script of this repository.

An entry that no longer matches anything is itself a finding, so the list cannot rot.
