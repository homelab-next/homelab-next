<!-- SPDX-License-Identifier: Apache-2.0 -->
# Customizations

A **customization** is a first-class record of one lab- or vendor-specific deviation from the
core. The core stays clean; every deviation lives in a file that has an owner, a reason and a
review date, so one-offs are visible and cannot quietly become permanent.

```text
core (generic, versioned)  <-- sanctioned extension points only -->  customizations (yours)
```

## Customize, contribute, or write an adapter?

Ask in this order and stop at the first yes:

1. **Is the core wrong or missing a knob for everyone?** Contribute upstream (a pull request,
   plus an ADR if a contract changes). Use a customization only as the stopgap, with
   `upstream: proposed`.
2. **Is it a different product behind an existing capability?** Write an **adapter** (a module
   implementing the capability contract and passing its conformance test). Not a customization.
3. **Is it specific to your hardware, network or household and nobody else needs it?** That is a
   customization, and the reason belongs in the file.
4. **Is it private content (rules, charters, secrets, values)?** That is overlay data, not a
   deviation. Keep it in your overlay.

## What a customization may do

Exactly five things, because these are the only extension points the applier knows:

| `kind` | Extension point | Claim string (used for conflict detection) |
|---|---|---|
| `override` | an Ansible variable of a role, which must already exist in its defaults and carry the role prefix | `var:<role>.<variable>` |
| `hook` | tasks that run `pre` or `post` one role entry point from [role-interface.md](role-interface.md) | `hook:<role>.<entry>.<phase>` |
| `patch-overlay` | a template overlay for a role template, by name (`append`, `prepend`, `replace`) | `template:<role>/<name>` |
| `registry-patch` | field changes on one registry service row; the patched registry must still pass the service schema | `registry:<service>.<field>` |
| `profile` | an opt-in host profile that adds named tasks | `profile:<name>` |

What it can never do: edit a core file, bypass a schema, point outside its own directory (absolute
and `..` paths are rejected, symlink escapes are resolved and rejected, paths into core are
rejected), or carry a raw endpoint (the same detection as `tools/no_raw_endpoints.py` runs on the
file and on every file it references). The applier writes nothing; it produces a **plan** and a
**resolved view**, and refuses to save even those inside a core directory.

## The file

One document per file, named `customization.yml` (or `*.customization.yml`, `.json`):

```yaml
id: custom:board-sensor-driver        # custom:<slug>, no long digit runs
title: Persist the sensor-chip kernel module on boards that need it
kind: profile
optional: true                         # shipped opt-in profiles only; inert until enabled
scope:                                 # at least one selector, logical ids and names
  capabilities: ["cap:monitoring"]     # also: services ["svc:..."], roles [...], hosts [...]
contract: adr:role-interface-and-capability-groups   # what it deviates from: cap:, adr: or a schema $id
reason: >-                             # required, human text, 20+ characters
  Why the core cannot or should not do this.
owner: platform-team                   # required
created: "2026-10-15"
review_by: "2027-06-30"                # required (unless maintained_upstream); at most 366 days after created
# maintained_upstream: true            # schema 1.1, shipped profiles only; see "Shipped profiles never expire"
links: {lesson: <uid>, runbook: <uid>}   # optional: records by uid (a legacy LL-900 still resolves)
upstream: proposed                     # none | proposed | accepted
upstream_ref: where the proposal lives # optional
action: { ... }                        # shape depends on kind; see schemas/platform/customization.schema.json
```

Schema: `schemas/platform/customization.schema.json`. Worked examples (one per kind) and 24
negatives live next to it.

## Where they live

* **Shipped optional profiles** are in `profiles/` in the repository. They are always loaded and
  linted, and applied only when a deployment enables them. Treat them as templates: copy one into
  your own directory and change it.
* **Your own** go in a directory outside the repository, found through (all combined, in this
  order): the `--config` file (or `HNX_CUSTOMIZATIONS_CONFIG`), repeated `--dir` flags, and the
  `HNX_CUSTOMIZATIONS_DIR` environment variable (several directories separated by `:`).

```yaml
# customizations.config.yml
customizations_dir: /path/to/my-overlay/customizations
enable:
  - id: custom:board-sensor-driver
    hosts: [host-a, host-b]     # narrows the shipped profile to these registry hosts
```

## Commands

```sh
hnx custom list                       # id, kind, state (active|inactive|expired|invalid), owner, review_by
hnx custom check [--strict]           # lint everything; exit 1 on any error (warnings too with --strict)
hnx custom plan  [--out plan.json]    # what WOULD change; exit 1 if anything is invalid or conflicting
hnx custom register OUT_DIR           # customizations.html + customizations.json
```

Useful flags: `--dir`, `--config`, `--enable ID[=HOST,HOST]`, `--root` (the tree supplying the
registry, roles, schemas and ADRs), `--today YYYY-MM-DD` (for reproducible runs), `--json`.

Lint rules `CU001`..`CU015` are listed at the top of `homelabnext/customization/lint.py`. The
ones people hit: `CU001` missing reason, owner or review date; `CU005` a scope selector that does
not resolve; `CU008` expired; `CU011` two customizations claim one extension point on overlapping
scope; `CU015` `maintained_upstream: true` outside the project's own shipped profiles.

## Conflicts and ordering

Two active customizations that claim the same extension point on overlapping scope are a
conflict, and the plan excludes both and fails. Scopes overlap when their resolved host sets
intersect; a scope that cannot be expanded to hosts is treated as overlapping, because "I cannot
tell" is the unsafe answer. Order is fixed: registry patches, variable overrides, template
overlays, hooks, then profiles, each sorted by id. The same inputs give a byte-identical plan.

## Lifecycle: add, review, upstream or retire

1. **Add.** Write the file with a reason a stranger could follow, an owner who will answer, and a
   `review_by` no more than a year out. Link the lesson or runbook that explains it. Run
   `hnx custom check` and `hnx custom plan`.
2. **Review.** At `review_by` the customization expires: `hnx custom check` and the standing
   invariant **X-09** (customizations are owned and not expired) go red until someone decides.
   Fourteen days before, `CU009` warns. Renewing means a new date and a reason that still holds.
3. **Upstream or retire.** If the deviation is generic, send it upstream and set
   `upstream: proposed`. When the change is merged set `upstream: accepted`; `CU014` then reminds
   you to delete the customization after the next upgrade. If the reason is gone, delete the file.

An expired customization is never applied. That is deliberate: a deviation nobody has looked at
for a year is the most likely thing to be wrong.

## Shipped profiles never expire (`maintained_upstream`)

Schema 1.1 adds one optional boolean, `maintained_upstream` (default `false`). It means the
customization is a profile that the project itself ships and maintains. Such an entry is exempt
from the `review_by` expiry rule (`CU008`/`CU009`) and from the one-year horizon rule, and
`review_by` becomes optional for it (keeping one is harmless). Every other customization still
needs a `review_by` and still expires. Schema 1.0 documents validate unchanged.

* **Provenance is the loader's source root, not the file.** The exemption is honoured only for
  documents loaded from the project's own `profiles/` directory. In any overlay directory
  (`--dir`, `HNX_CUSTOMIZATIONS_DIR`, a config file's `customizations_dir`, `customizations/`)
  the flag is rejected with `CU015`, the customization is not exempt, and it still expires. A
  file cannot grant itself the exemption by saying so.
* `hnx custom check` and the standing invariant **X-09** honour it: shipped profiles pass at any
  future date, overlay customizations with an old `review_by` still fail. `hnx custom list` and
  the register mark upstream-maintained entries.
* A non-boolean value fails the schema.

**Why not just give shipped profiles a far-future `review_by`?** Because that is the "never
expires in disguise" the horizon rule exists to forbid: the date is a lie nobody will notice
until it fires years later, it makes the shipped files churn every year to push the date, and it
teaches overlay authors that a distant date is an acceptable way to opt out of review. Expiry is
a promise that a human owner re-reads a deviation. A shipped profile has no such owner on the
deployment side: the project reviews it with each release, and the deployment cannot renew it.
Making that explicit in a field, enforced by where the file was loaded from, is honest and
cannot be abused.

## The invariant and the register

`homelabnext/customization/plugins/x09_customizations.py` is an invariants plugin (pillar X
style). Load it with `--plugins-dir homelabnext/customization/plugins` or the
`homelabnext.invariants.checks` entry-point group. It passes when every customization found has a
valid schema (so reason, owner and review date exist), coherent dates, no expiry and no conflict;
it skips when there is none; it errors if the loader itself breaks.

`hnx custom register OUT_DIR` writes a static page and a JSON file in the same style as the other
registers: one card per customization with its state, owner, days left, contract and claims.

## Shipped example profiles

All synthetic; see [profiles/README.md](../profiles/README.md).

* `board-sensor-driver`: a `profile` that persists a sensor kernel module on allowlisted boards.
* `vlan-aware-bridge-verifier`: a read-only `profile` that fails when a bridge is not VLAN-aware.
* `reverse-proxy-tunnel-workaround`: a `patch-overlay` appending one setting to a role template.

## Deliberate limits

* Nothing here can be tested against hardware; the profiles' task files are linted and planned,
  not executed. Running them on a real host is SERVER-side validation.
* The applier computes and validates; wiring `plan` output into playbook runs (feeding
  `resolved.role_vars` as extra vars, including hook files) is the playbook layer's job.
